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

#ifndef _GATEKEEPER_ACL_H_
#define _GATEKEEPER_ACL_H_

#include "gatekeeper_config.h"
#include "gatekeeper_net.h"

/* Fields that can be checked in an IPv6 ACL rule. */
enum {
	PROTO_FIELD_IPV6,
	DST1_FIELD_IPV6,
	DST2_FIELD_IPV6,
	DST3_FIELD_IPV6,
	DST4_FIELD_IPV6,
	SRCP_FIELD_IPV6,
	DSTP_FIELD_IPV6,
	TYPE_FIELD_ICMPV6,
	NUM_FIELDS_IPV6,
};

extern struct rte_acl_field_def ipv6_defs[NUM_FIELDS_IPV6];
RTE_ACL_RULE_DEF(ipv6_acl_rule, RTE_DIM(ipv6_defs));

struct acl_search {
	/* References to the start of the IPv6 header in each packet. */
	const uint8_t   *data[GATEKEEPER_MAX_PKT_BURST];
	/* References to each packet's mbuf. */
	struct rte_mbuf *mbufs[GATEKEEPER_MAX_PKT_BURST];
	/* The classification results for each packet. */
	uint32_t        res[GATEKEEPER_MAX_PKT_BURST];
	/* The number of packets held for classification. */
	unsigned int    num;
};

/* Allocate and free IPv6 ACLs. */
int init_ipv6_acls(struct gatekeeper_if *iface);
void destroy_ipv6_acls(struct gatekeeper_if *iface);

/* Register IPv6 ACL rules and callback functions. */
int register_ipv6_acl(struct ipv6_acl_rule *rules, unsigned int num_rules,
	acl_cb_func cb_f, struct gatekeeper_if *iface);

/* Build the ACL trie. This should be invoked after all ACL rules are added. */
int build_ipv6_acls(struct gatekeeper_if *iface);

/* Classify batches of packets in @acl and invoke callback functions. */
int process_ipv6_acl(struct gatekeeper_if *iface, unsigned int lcore_id,
	struct acl_search *acl);

/* Definitions for blocks making use of the IPv6 ACLs. */

#define IPV6_ACL_SEARCH_DEF(name) struct acl_search name = { .num = 0, }

/* This function expects that the mbuf includes the Ethernet header. */
static inline void
add_pkt_ipv6_acl(struct acl_search *acl, struct rte_mbuf *pkt)
{
	acl->data[acl->num] = rte_pktmbuf_mtod_offset(pkt, uint8_t *,
		sizeof(struct ether_hdr));
	acl->mbufs[acl->num] = pkt;
	acl->num++;
}

static inline int
process_pkts_ipv6_acl(struct gatekeeper_if *iface, unsigned int lcore,
	struct acl_search *acl)
{
	if (acl->num == 0)
		return 0;
	return process_ipv6_acl(iface, lcore, acl);
}

#endif /* _GATEKEEPER_ACL_H_ */
