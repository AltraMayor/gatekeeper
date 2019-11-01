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
#include "gatekeeper_l2.h"
#include "gatekeeper_net.h"

struct acl_search {
	/* The number of packets held for classification. */
	unsigned int    num;
	/* Fixed field here. */
	const uint8_t   **data;
	/* List of references to each packet's mbuf. */
	struct rte_mbuf **mbufs;
};

/*
 * Declare and initialize a struct acl_search.
 *
 * This struct must not be passed to destroy_acl_search().
 * Assuming that it's empty, just let the struct go out of scope.
 */
#define DEFINE_ACL_SEARCH(name, num_pkts)			\
	const uint8_t *name##_data_array[(num_pkts)];		\
	struct rte_mbuf *name##_mbufs_array[(num_pkts)];	\
	struct acl_search name = {				\
		.num = 0,					\
		.data = name##_data_array,			\
		.mbufs = name##_mbufs_array,			\
	}

struct acl_search *alloc_acl_search(uint8_t num_pkts);
void destroy_acl_search(struct acl_search *acl);

/* Classify batches of packets in @acl and invoke callback functions. */
int process_acl(struct gatekeeper_if *iface, unsigned int lcore_id,
	struct acl_search *acl, struct acl_state *astate,
	int acl_enabled, const char *proto_name);
/* Free ACLs. */
void destroy_acls(struct acl_state *astate);

/* This function expects that the mbuf includes the Ethernet header. */
static inline void
add_pkt_acl(struct acl_search *acl, struct rte_mbuf *pkt)
{
	/* pkt_in_skip_l2() was already called by GK or GT. */
	acl->data[acl->num] = rte_pktmbuf_mtod_offset(pkt, uint8_t *,
		pkt_in_l2_hdr_len(pkt));
	acl->mbufs[acl->num] = pkt;
	acl->num++;
}

static inline int
ipv4_acl_enabled(struct gatekeeper_if *iface)
{
	/*
	 * The IPv4 ACL is only needed for interfaces that have
	 * IPv4 addresses and don't support the ntuple filter.
	 */
	return !iface->hw_filter_ntuple && ipv4_if_configured(iface);
}

static inline int
ipv6_acl_enabled(struct gatekeeper_if *iface)
{
	/* The IPv6 ACL is needed whenever an interface has an IPv6 address. */
	return ipv6_if_configured(iface);
}

static inline int
process_pkts_acl(struct gatekeeper_if *iface, unsigned int lcore,
	struct acl_search *acl, uint16_t proto)
{
	if (acl->num == 0)
		return 0;

	switch (proto) {
	case RTE_ETHER_TYPE_IPV4:
		return process_acl(iface, lcore, acl, &iface->ipv4_acls,
			ipv4_acl_enabled(iface), "IPv4");
	case RTE_ETHER_TYPE_IPV6:
		return process_acl(iface, lcore, acl, &iface->ipv6_acls,
			ipv6_acl_enabled(iface), "IPv6");
	default:
		rte_panic("%s: called on unknown protocol %hu\n",
			__func__, proto);
	}
}

/*
 * IPv4 ACLs.
 */

/* Fields that can be checked in an IPv4 ACL rule. */
enum {
	PROTO_FIELD_IPV4,
	DST_FIELD_IPV4,
	SRCP_FIELD_IPV4,
	DSTP_FIELD_IPV4,
	TYPE_FIELD_ICMP,
	NUM_FIELDS_IPV4,
};

extern struct rte_acl_field_def ipv4_defs[NUM_FIELDS_IPV4];
RTE_ACL_RULE_DEF(ipv4_acl_rule, RTE_DIM(ipv4_defs));

/* Allocate IPv4 ACLs. */
int init_ipv4_acls(struct gatekeeper_if *iface);

/* Register IPv4 ACL rules and callback functions. */
int register_ipv4_acl(struct ipv4_acl_rule *rules, unsigned int num_rules,
	acl_cb_func cb_f, ext_cb_func ext_cb_f, struct gatekeeper_if *iface);

/* Build the ACL trie. This should be invoked after all ACL rules are added. */
int build_ipv4_acls(struct gatekeeper_if *iface);

/*
 * IPv6 ACLs.
 */

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

/* Allocate IPv6 ACLs. */
int init_ipv6_acls(struct gatekeeper_if *iface);

/* Register IPv6 ACL rules and callback functions. */
int register_ipv6_acl(struct ipv6_acl_rule *rules, unsigned int num_rules,
	acl_cb_func cb_f, ext_cb_func ext_cb_f, struct gatekeeper_if *iface);

/* Build the ACL trie. This should be invoked after all ACL rules are added. */
int build_ipv6_acls(struct gatekeeper_if *iface);

#endif /* _GATEKEEPER_ACL_H_ */
