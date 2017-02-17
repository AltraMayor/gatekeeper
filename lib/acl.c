/*
 * Gatekeeper - DoS protection system.
 * Copyright (C) 2016 Digirati LTDA.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "gatekeeper_acl.h"
#include "gatekeeper_lls.h"

/* Maximum number of rules installed per ACL. */
#define MAX_NUM_IPV6_ACL_RULES (32)

/* Callback function for when there's no classification match. */
static inline int
drop_ipv6_acl_pkts(struct rte_mbuf **pkts, int num_pkts,
	__attribute__((unused)) struct gatekeeper_if *iface)
{
	int i;
	for (i = 0; i < num_pkts; i++)
		rte_pktmbuf_free(pkts[i]);
	return 0;
}

/*
 * All IPv6 fields involved in classification; not all fields must
 * be specified for every rule. Fields must be grouped into sets of
 * four bytes, except for the first field.
 */
struct rte_acl_field_def ipv6_defs[NUM_FIELDS_IPV6] = {
	{
		.type = RTE_ACL_FIELD_TYPE_BITMASK,
		.size = sizeof(uint8_t),
		.field_index = PROTO_FIELD_IPV6,
		.input_index = PROTO_FIELD_IPV6,
		.offset = offsetof(struct ipv6_hdr, proto),
	},
	{
		.type = RTE_ACL_FIELD_TYPE_MASK,
		.size = sizeof(uint32_t),
		.field_index = DST1_FIELD_IPV6,
		.input_index = DST1_FIELD_IPV6,
		.offset = offsetof(struct ipv6_hdr, dst_addr[0]),
	},
	{
		.type = RTE_ACL_FIELD_TYPE_MASK,
		.size = sizeof(uint32_t),
		.field_index = DST2_FIELD_IPV6,
		.input_index = DST2_FIELD_IPV6,
		.offset = offsetof(struct ipv6_hdr, dst_addr[4]),
	},
	{
		.type = RTE_ACL_FIELD_TYPE_MASK,
		.size = sizeof(uint32_t),
		.field_index = DST3_FIELD_IPV6,
		.input_index = DST3_FIELD_IPV6,
		.offset = offsetof(struct ipv6_hdr, dst_addr[8]),
	},
	{
		.type = RTE_ACL_FIELD_TYPE_MASK,
		.size = sizeof(uint32_t),
		.field_index = DST4_FIELD_IPV6,
		.input_index = DST4_FIELD_IPV6,
		.offset = offsetof(struct ipv6_hdr, dst_addr[12]),
	},
	{
		/* Enforce grouping into four bytes. */
		.type = RTE_ACL_FIELD_TYPE_BITMASK,
		.size = sizeof(uint32_t),
		.field_index = TYPE_FIELD_ICMPV6,
		.input_index = TYPE_FIELD_ICMPV6,
		.offset = sizeof(struct ipv6_hdr) +
			offsetof(struct icmpv6_hdr, type),
	},
};

int
register_ipv6_acl(struct ipv6_acl_rule *ipv6_rules, unsigned int num_rules,
	acl_cb_func cb_f, struct gatekeeper_if *iface)
{
	unsigned int numa_nodes = get_net_conf()->numa_nodes;
	unsigned int i;

	if (iface->acl_func_count == GATEKEEPER_IPV6_ACL_MAX) {
		RTE_LOG(ERR, GATEKEEPER, "acl: cannot install more ACL types on the %s iface\n",
			iface->name);
		return -1;
	}

	/* Assign a new ID for this rule type. */
	for (i = 0; i < num_rules; i++)
		ipv6_rules[i].data.userdata = iface->acl_func_count;

	for (i = 0; i < numa_nodes; i++) {
		int ret = rte_acl_add_rules(iface->ipv6_acls[i],
			(struct rte_acl_rule *)ipv6_rules, num_rules);
		if (ret < 0) {
			RTE_LOG(ERR, ACL, "Failed to add ACL rules on the %s interface on socket %d\n",
				iface->name, i);
			return ret;
		}
	}

	iface->acl_funcs[iface->acl_func_count] = cb_f;
	iface->acl_func_count++;

	return 0;
}

int
process_ipv6_acl(struct gatekeeper_if *iface, unsigned int lcore_id,
	struct acl_search *acl)
{
	struct rte_mbuf *pkts[iface->acl_func_count][GATEKEEPER_MAX_PKT_BURST];
	int num_pkts[iface->acl_func_count];
	unsigned int socket_id = rte_lcore_to_socket_id(lcore_id);
	unsigned int i;
	int ret;

	if (unlikely(!ipv6_if_configured(iface))) {
		drop_ipv6_acl_pkts(acl->mbufs, acl->num, iface);
		acl->num = 0;
		return 0;
	}

	ret = rte_acl_classify(iface->ipv6_acls[socket_id],
		acl->data, acl->res, acl->num, 1);
	if (unlikely(ret < 0)) {
		RTE_LOG(ERR, ACL,
			"invalid arguments given to rte_acl_classify()\n");
		drop_ipv6_acl_pkts(acl->mbufs, acl->num, iface);
		acl->num = 0;
		return ret;
	}

	/* Split packets into separate buffers -- one for each type. */
	memset(num_pkts, 0, sizeof(num_pkts));
	for (i = 0; i < acl->num; i++) {
		int type = acl->res[i];
		pkts[type][num_pkts[type]++] = acl->mbufs[i];
	}

	/* Transmit separate buffers to registered ACL functions. */
	for (i = 0; i < iface->acl_func_count; i++) {
		if (num_pkts[i] == 0)
			continue;

		ret = iface->acl_funcs[i](pkts[i], num_pkts[i], iface);
		if (unlikely(ret < 0)) {
			/*
			 * Each ACL function is responsible for
			 * freeing packets not already handled.
			 */
			RTE_LOG(WARNING, GATEKEEPER,
				"acl: ACL function %d failed on %s iface\n",
				i, iface->name);
		}
	}

	acl->num = 0;
	return 0;
}

int
build_ipv6_acls(struct gatekeeper_if *iface)
{
	struct rte_acl_config acl_build_params;
	unsigned int numa_nodes = get_net_conf()->numa_nodes;
	unsigned int i;

	memset(&acl_build_params, 0, sizeof(acl_build_params));
	acl_build_params.num_categories = 1;
	acl_build_params.num_fields = RTE_DIM(ipv6_defs);
	rte_memcpy(&acl_build_params.defs, ipv6_defs, sizeof(ipv6_defs));

	for (i = 0; i < numa_nodes; i++) {
		int ret = rte_acl_build(iface->ipv6_acls[i], &acl_build_params);
		if (ret < 0) {
			RTE_LOG(ERR, ACL,
				"Failed to build IPv6 ACL for the %s iface\n",
				iface->name);
			return ret;
		}
	}

	return 0;
}

int
init_ipv6_acls(struct gatekeeper_if *iface)
{
	unsigned int numa_nodes = get_net_conf()->numa_nodes;
	unsigned int i;

	for (i = 0; i < numa_nodes; i++) {
		char acl_name[64];
		struct rte_acl_param acl_params = {
			.socket_id = i,
			.rule_size = RTE_ACL_RULE_SZ(RTE_DIM(ipv6_defs)),
			.max_rule_num = MAX_NUM_IPV6_ACL_RULES,
		};
		int ret = snprintf(acl_name, sizeof(acl_name),
			"%s_%u", iface->name, i);
		RTE_VERIFY(ret > 0 && ret < (int)sizeof(acl_name));
		acl_params.name = acl_name;

		iface->ipv6_acls[i] = rte_acl_create(&acl_params);
		if (iface->ipv6_acls[i] == NULL) {
			unsigned int j;

			RTE_LOG(ERR, ACL, "Failed to create IPv6 ACL for the %s iface on socket %d\n",
				iface->name, i);
			for (j = 0; j < i; j++) {
				rte_acl_free(iface->ipv6_acls[i]);
				iface->ipv6_acls[i] = NULL;
			}
			return -1;
		}
	}

	/* Add drop function for packets that have no match. */
	RTE_VERIFY(RTE_ACL_INVALID_USERDATA == 0);
	iface->acl_funcs[RTE_ACL_INVALID_USERDATA] = drop_ipv6_acl_pkts;
	iface->acl_func_count = 1;

	return 0;
}

void
destroy_ipv6_acls(struct gatekeeper_if *iface)
{
	unsigned int numa_nodes = get_net_conf()->numa_nodes;
	unsigned int i;
	for (i = 0; i < numa_nodes; i++) {
		rte_acl_free(iface->ipv6_acls[i]);
		iface->ipv6_acls[i] = NULL;
	}
}
