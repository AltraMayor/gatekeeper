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

#include <rte_icmp.h>

#include "gatekeeper_acl.h"
#include "gatekeeper_lls.h"

/* Maximum number of rules installed per ACL. */
#define MAX_NUM_ACL_RULES (32)

/* Result returned when the ACL does not find a matching rule. */
#define ACL_NO_MATCH (0)

/* Callback function for when there's no classification match. */
static int
drop_unmatched_pkts(struct rte_mbuf **pkts, unsigned int num_pkts,
	__attribute__((unused)) struct gatekeeper_if *iface)
{
	unsigned int i;
	for (i = 0; i < num_pkts; i++) {
		/*
		 * WARNING
		 *   A packet has reached a Gatekeeper server,
		 *   and Gatekeeper doesn't know what to do with
		 *   this packet. If attackers are able to send
		 *   these packets, they may be able to slow
		 *   Gatekeeper down since Gatekeeper does a lot of
		 *   processing to eventually discard these packets.
		 */
		if (unlikely(G_LOG_CHECK(DEBUG))) {
			G_LOG(DEBUG,
				"acl: a packet failed to match any ACL rules, the whole packet is dumped below:\n");
			rte_pktmbuf_dump(log_file, pkts[i], pkts[i]->pkt_len);
		}
		rte_pktmbuf_free(pkts[i]);
	}

	return 0;
}

int
process_acl(struct gatekeeper_if *iface, unsigned int lcore_id,
	struct acl_search *acl, struct acl_state *astate,
	int acl_enabled, const char *proto_name)
{
	struct rte_mbuf *pkts[astate->func_count][acl->num];
	int num_pkts[astate->func_count];
	unsigned int socket_id = rte_lcore_to_socket_id(lcore_id);
	unsigned int i;
	int ret;
	/* The classification results for each packet. */
	uint32_t res[acl->num];

	if (!acl_enabled) {
		ret = 0;
		goto drop_acl_pkts;
	}

	ret = rte_acl_classify(astate->acls[socket_id],
		acl->data, res, acl->num, 1);
	if (unlikely(ret < 0)) {
		G_LOG(ERR,
			"acl: invalid arguments given to %s rte_acl_classify()\n",
			proto_name);
		goto drop_acl_pkts;
	}

	/* Split packets into separate buffers -- one for each type. */
	memset(num_pkts, 0, sizeof(num_pkts));
	for (i = 0; i < acl->num; i++) {
		int type = res[i];
		if (type == ACL_NO_MATCH) {
			unsigned int j;
			/*
			 * @j starts at 1 to skip ACL_NO_MATCH,
			 * which has no matching function.
			 */
			for (j = 1; j < astate->func_count; j++) {
				/* Skip over ACLs without matching function. */
				if (astate->ext_funcs[j] == NULL)
					continue;
				ret = astate->ext_funcs[j](
					acl->mbufs[i], iface);
				if (ret == 0) {
					type = j;
					break;
				}
			}
		}

		pkts[type][num_pkts[type]++] = acl->mbufs[i];
	}

	/* Transmit separate buffers to registered ACL functions. */
	for (i = 0; i < astate->func_count; i++) {
		if (num_pkts[i] == 0)
			continue;

		ret = astate->funcs[i](pkts[i], num_pkts[i], iface);
		if (unlikely(ret < 0)) {
			/*
			 * Each ACL function is responsible for
			 * freeing packets not already handled.
			 */
			G_LOG(WARNING,
				"acl: %s ACL function %d failed on %s iface\n",
				proto_name, i, iface->name);
		}
	}

	ret = 0;
	goto out;

drop_acl_pkts:

	for (i = 0; i < acl->num; i++)
		rte_pktmbuf_free(acl->mbufs[i]);

out:
	acl->num = 0;
	return ret;
}

void
destroy_acls(struct acl_state *astate)
{
	unsigned int numa_nodes = get_net_conf()->numa_nodes;
	unsigned int i;
	for (i = 0; i < numa_nodes; i++) {
		if (astate->acls[i] != NULL) {
			rte_acl_free(astate->acls[i]);
			astate->acls[i] = NULL;
		}
	}
	astate->enabled = false;
}

/*
 * IPv4 ACLs.
 */

/*
 * Input indices for the IPv4-related ACL fields. Fields are given
 * unique identifiers, but since the DPDK ACL library processes
 * each packet in four-byte chunks, the fields need to be grouped
 * into four-byte input indices. Therefore, adjacent fields may
 * share the same input index. For example, TCP and UDP ports are
 * two-byte contiguous fields forming four consecutive bytes, so
 * they could have the same input index.
 */
enum {
	PROTO_INPUT_IPV4,
	DST_INPUT_IPV4,
	/* Source/destination ports are grouped together. */
	PORTS_INPUT_IPV4,
	TYPE_INPUT_ICMP,
	NUM_INPUTS_IPV4,
};

/*
 * All IPv4 fields involved in classification; not all fields must
 * be specified for every rule. Fields must be grouped into sets of
 * four bytes, except for the first field.
 */
struct rte_acl_field_def ipv4_defs[NUM_FIELDS_IPV4] = {
	{
		.type = RTE_ACL_FIELD_TYPE_BITMASK,
		.size = sizeof(uint8_t),
		.field_index = PROTO_FIELD_IPV4,
		.input_index = PROTO_INPUT_IPV4,
		.offset = offsetof(struct rte_ipv4_hdr, next_proto_id),
	},
	{
		.type = RTE_ACL_FIELD_TYPE_MASK,
		.size = sizeof(uint32_t),
		.field_index = DST_FIELD_IPV4,
		.input_index = DST_INPUT_IPV4,
		.offset = offsetof(struct rte_ipv4_hdr, dst_addr),
	},
	/*
	 * The source and destination ports are the first and second
	 * fields in TCP and UDP, so they are the four bytes directly
	 * following the IPv4 header.
	 */
	{
		.type = RTE_ACL_FIELD_TYPE_BITMASK,
		.size = sizeof(uint16_t),
		.field_index = SRCP_FIELD_IPV4,
		.input_index = PORTS_INPUT_IPV4,
		.offset = sizeof(struct rte_ipv4_hdr),
	},
	{
		.type = RTE_ACL_FIELD_TYPE_BITMASK,
		.size = sizeof(uint16_t),
		.field_index = DSTP_FIELD_IPV4,
		.input_index = PORTS_INPUT_IPV4,
		.offset = sizeof(struct rte_ipv4_hdr) + sizeof(uint16_t),
	},
};

static int
register_cb_fs(struct acl_state *acls, acl_cb_func cb_f, ext_cb_func ext_cb_f)
{
	unsigned int i, func_count = acls->func_count;

	if (ext_cb_f == NULL) {
		/*
		 * Since @ext_cb_f is NULL,
		 * we only care to where the packets are going.
		 * Combining types is important to group more packets for
		 * each call of @cb_f.
		 */
		for (i = 0; i < func_count; i++) {
			if (acls->funcs[i] == cb_f)
				return i;
		}
		goto new_type;
	}

	for (i = 0; i < func_count; i++) {
		if (acls->ext_funcs[i] == ext_cb_f) {
			if (acls->funcs[i] == cb_f)
				return i;
			G_LOG(ERR, "acl: an extension callback function is being used twice, but has different callback functions associated to it\n");
			return -1;
		}
	}

new_type:
	if (func_count >= GATEKEEPER_ACL_MAX) {
		G_LOG(ERR, "acl: cannot install more ACL types\n");
		return -1;
	}

	acls->funcs[func_count] = cb_f;
	acls->ext_funcs[func_count] = ext_cb_f;
	acls->func_count++;
	return func_count;
}

/*
 * For each ACL rule set, register a match function that parses
 * the unmatched IPv4 packets, and direct them to the corresponding
 * blocks or drop them. This functionality is for the ext_cb_f parameter
 * and that it's necessary because of variable IP headers that
 * may not match the ACLs.
 *
 * WARNING
 *   You must only register filters that are not subject to
 *   the control of attackers. Otherwise, attackers can overwhelm
 *   Gatekeeper servers since the current implementation of these filters
 *   is not very efficient due to the variable header of IP.
 */
int
register_ipv4_acl(struct ipv4_acl_rule *ipv4_rule,
	acl_cb_func cb_f, ext_cb_func ext_cb_f,
	struct gatekeeper_if *iface)
{
	unsigned int i, numa_nodes = get_net_conf()->numa_nodes;
	int index = register_cb_fs(&iface->ipv4_acls, cb_f, ext_cb_f);

	if (index < 0) {
		G_LOG(ERR, "acl: cannot add IPv4 ACL type on interface %s\n",
			iface->name);
		return -1;
	}

	/* Assign an ID to this rule. */
	ipv4_rule->data.userdata = index;

	for (i = 0; i < numa_nodes; i++) {
		int ret;

		if (iface->ipv4_acls.acls[i] == NULL)
			continue;

		ret = rte_acl_add_rules(iface->ipv4_acls.acls[i],
			(struct rte_acl_rule *)ipv4_rule, 1);
		if (ret < 0) {
			G_LOG(ERR, "acl: failed to add IPv4 ACL rule on interface %s on socket %d\n",
				iface->name, i);
			return ret;
		}
	}

	return 0;
}

int
build_ipv4_acls(struct gatekeeper_if *iface)
{
	struct rte_acl_config acl_build_params;
	unsigned int numa_nodes = get_net_conf()->numa_nodes;
	unsigned int i;

	memset(&acl_build_params, 0, sizeof(acl_build_params));
	acl_build_params.num_categories = 1;
	acl_build_params.num_fields = RTE_DIM(ipv4_defs);
	rte_memcpy(&acl_build_params.defs, ipv4_defs, sizeof(ipv4_defs));

	for (i = 0; i < numa_nodes; i++) {
		int ret;

		if (iface->ipv4_acls.acls[i] == NULL)
			continue;

		ret = rte_acl_build(iface->ipv4_acls.acls[i],
			&acl_build_params);
		if (ret < 0) {
			G_LOG(ERR,
				"acl: failed to build IPv4 ACL for the %s iface\n",
				iface->name);
			return ret;
		}
	}

	return 0;
}

int
init_ipv4_acls(struct gatekeeper_if *iface)
{
	struct net_config *net_conf = get_net_conf();
	unsigned int i;

	for (i = 0; i < net_conf->numa_nodes; i++) {
		char acl_name[64];
		struct rte_acl_param acl_params = {
			.socket_id = i,
			.rule_size = RTE_ACL_RULE_SZ(RTE_DIM(ipv4_defs)),
			.max_rule_num = MAX_NUM_ACL_RULES,
		};
		int ret;

		if (!net_conf->numa_used[i])
			continue;

		ret = snprintf(acl_name, sizeof(acl_name),
			"%s_%u_v4", iface->name, i);
		RTE_VERIFY(ret > 0 && ret < (int)sizeof(acl_name));
		acl_params.name = acl_name;

		iface->ipv4_acls.acls[i] = rte_acl_create(&acl_params);
		if (iface->ipv4_acls.acls[i] == NULL) {
			unsigned int j;

			G_LOG(ERR, "acl: failed to create IPv4 ACL for the %s iface on socket %d\n",
				iface->name, i);
			for (j = 0; j < i; j++) {
				rte_acl_free(iface->ipv4_acls.acls[i]);
				iface->ipv4_acls.acls[i] = NULL;
			}
			return -1;
		}
	}

	/* Add drop function for packets that cannot be classified. */
	RTE_BUILD_BUG_ON(ACL_NO_MATCH != 0);
	iface->ipv4_acls.funcs[ACL_NO_MATCH] = drop_unmatched_pkts;
	iface->ipv4_acls.ext_funcs[ACL_NO_MATCH] = NULL;
	iface->ipv4_acls.func_count = 1;
	iface->ipv4_acls.enabled = true;

	return 0;
}

/*
 * IPv6 ACLs.
 */

/*
 * Input indices for the IPv6-related ACL fields. Fields are given
 * unique identifiers, but since the DPDK ACL library processes
 * each packet in four-byte chunks, the fields need to be grouped
 * into four-byte input indices. Therefore, adjacent fields may
 * share the same input index. For example, TCP and UDP ports are
 * two-byte contiguous fields forming four consecutive bytes, so
 * they could have the same input index.
 */
enum {
	PROTO_INPUT_IPV6,
	DST1_INPUT_IPV6,
	DST2_INPUT_IPV6,
	DST3_INPUT_IPV6,
	DST4_INPUT_IPV6,
	/* Source/destination ports are grouped together. */
	PORTS_INPUT_IPV6,
	TYPE_INPUT_ICMPV6,
	NUM_INPUTS_IPV6,
};

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
		.input_index = PROTO_INPUT_IPV6,
		.offset = offsetof(struct rte_ipv6_hdr, proto),
	},
	{
		.type = RTE_ACL_FIELD_TYPE_MASK,
		.size = sizeof(uint32_t),
		.field_index = DST1_FIELD_IPV6,
		.input_index = DST1_INPUT_IPV6,
		.offset = offsetof(struct rte_ipv6_hdr, dst_addr[0]),
	},
	{
		.type = RTE_ACL_FIELD_TYPE_MASK,
		.size = sizeof(uint32_t),
		.field_index = DST2_FIELD_IPV6,
		.input_index = DST2_INPUT_IPV6,
		.offset = offsetof(struct rte_ipv6_hdr, dst_addr[4]),
	},
	{
		.type = RTE_ACL_FIELD_TYPE_MASK,
		.size = sizeof(uint32_t),
		.field_index = DST3_FIELD_IPV6,
		.input_index = DST3_INPUT_IPV6,
		.offset = offsetof(struct rte_ipv6_hdr, dst_addr[8]),
	},
	{
		.type = RTE_ACL_FIELD_TYPE_MASK,
		.size = sizeof(uint32_t),
		.field_index = DST4_FIELD_IPV6,
		.input_index = DST4_INPUT_IPV6,
		.offset = offsetof(struct rte_ipv6_hdr, dst_addr[12]),
	},
	/*
	 * The source and destination ports are the first and second
	 * fields in TCP and UDP, so they are the four bytes directly
	 * following the IPv6 header.
	 */
	{
		.type = RTE_ACL_FIELD_TYPE_BITMASK,
		.size = sizeof(uint16_t),
		.field_index = SRCP_FIELD_IPV6,
		.input_index = PORTS_INPUT_IPV6,
		.offset = sizeof(struct rte_ipv6_hdr),
	},
	{
		.type = RTE_ACL_FIELD_TYPE_BITMASK,
		.size = sizeof(uint16_t),
		.field_index = DSTP_FIELD_IPV6,
		.input_index = PORTS_INPUT_IPV6,
		.offset = sizeof(struct rte_ipv6_hdr) + sizeof(uint16_t),
	},
	{
		/* Enforce grouping into four bytes. */
		.type = RTE_ACL_FIELD_TYPE_BITMASK,
		.size = sizeof(uint32_t),
		.field_index = TYPE_FIELD_ICMPV6,
		.input_index = TYPE_INPUT_ICMPV6,
		.offset = sizeof(struct rte_ipv6_hdr) +
			offsetof(struct icmpv6_hdr, type),
	},
};

/*
 * For each ACL rule set, register a match function that parses
 * the unmatched IPv6 packets, and direct them to the corresponding
 * blocks or drop them. This functionality is for the ext_cb_f parameter
 * and that it's necessary because of variable IP headers that
 * may not match the ACLs.
 *
 * WARNING
 *   You must only register filters that are not subject to
 *   the control of attackers. Otherwise, attackers can overwhelm
 *   Gatekeeper servers since the current implementation of these filters
 *   is not very efficient due to the variable header of IP.
 */
int
register_ipv6_acl(struct ipv6_acl_rule *ipv6_rule,
	acl_cb_func cb_f, ext_cb_func ext_cb_f,
	struct gatekeeper_if *iface)
{
	unsigned int i, numa_nodes = get_net_conf()->numa_nodes;
	int index = register_cb_fs(&iface->ipv6_acls, cb_f, ext_cb_f);

	if (index < 0) {
		G_LOG(ERR, "acl: cannot add IPv6 ACL type on interface %s\n",
			iface->name);
		return -1;
	}

	/* Assign an ID to this rule. */
	ipv6_rule->data.userdata = index;

	for (i = 0; i < numa_nodes; i++) {
		int ret;

		if (iface->ipv6_acls.acls[i] == NULL)
			continue;

		ret = rte_acl_add_rules(iface->ipv6_acls.acls[i],
			(struct rte_acl_rule *)ipv6_rule, 1);
		if (ret < 0) {
			G_LOG(ERR, "acl: failed to add IPv6 ACL rule on interface %s on socket %d\n",
				iface->name, i);
			return ret;
		}
	}

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
		int ret;

		if (iface->ipv6_acls.acls[i] == NULL)
			continue;

		ret = rte_acl_build(iface->ipv6_acls.acls[i],
			&acl_build_params);
		if (ret < 0) {
			G_LOG(ERR,
				"acl: failed to build IPv6 ACL for the %s iface\n",
				iface->name);
			return ret;
		}
	}

	return 0;
}

int
init_ipv6_acls(struct gatekeeper_if *iface)
{
	struct net_config *net_conf = get_net_conf();
	unsigned int i;

	for (i = 0; i < net_conf->numa_nodes; i++) {
		char acl_name[64];
		struct rte_acl_param acl_params = {
			.socket_id = i,
			.rule_size = RTE_ACL_RULE_SZ(RTE_DIM(ipv6_defs)),
			.max_rule_num = MAX_NUM_ACL_RULES,
		};
		int ret;

		if (!net_conf->numa_used[i])
			continue;

		ret = snprintf(acl_name, sizeof(acl_name),
			"%s_%u_v6", iface->name, i);
		RTE_VERIFY(ret > 0 && ret < (int)sizeof(acl_name));
		acl_params.name = acl_name;

		iface->ipv6_acls.acls[i] = rte_acl_create(&acl_params);
		if (iface->ipv6_acls.acls[i] == NULL) {
			unsigned int j;

			G_LOG(ERR, "acl: failed to create IPv6 ACL for the %s iface on socket %d\n",
				iface->name, i);
			for (j = 0; j < i; j++) {
				rte_acl_free(iface->ipv6_acls.acls[i]);
				iface->ipv6_acls.acls[i] = NULL;
			}
			return -1;
		}
	}

	/* Add drop function for packets that cannot be classified. */
	RTE_BUILD_BUG_ON(ACL_NO_MATCH != 0);
	iface->ipv6_acls.funcs[ACL_NO_MATCH] = drop_unmatched_pkts;
	iface->ipv6_acls.ext_funcs[ACL_NO_MATCH] = NULL;
	iface->ipv6_acls.func_count = 1;
	iface->ipv6_acls.enabled = true;

	return 0;
}
