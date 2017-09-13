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

#ifndef _GATEKEEPER_GK_H_
#define _GATEKEEPER_GK_H_

#include <rte_atomic.h>

#include "gatekeeper_fib.h"
#include "gatekeeper_net.h"
#include "gatekeeper_ipip.h"
#include "gatekeeper_ggu.h"
#include "gatekeeper_mailbox.h"
#include "gatekeeper_lpm.h"
#include "gatekeeper_sol.h"

/*
 * The LPM reserves 24-bit for the next-hop field.
 * TODO Drop the constant below and make it dynamic.
 */
#define GK_MAX_NUM_FIB_ENTRIES (256)

/*
 * A flow entry can be in one of three states:
 * request, granted, or declined.
 */
enum gk_flow_state { GK_REQUEST, GK_GRANTED, GK_DECLINED };

/* Structures for each GK instance. */
struct gk_instance {
	struct rte_hash   *ip_flow_hash_table;
	struct flow_entry *ip_flow_entry_table;

	struct acl_search *acl4;
	struct acl_search *acl6;

	/* RX queue on the front interface. */
	uint16_t          rx_queue_front;
	/* TX queue on the front interface. */
	uint16_t          tx_queue_front;
	/* RX queue on the back interface. */
	uint16_t          rx_queue_back;
	/* TX queue on the back interface. */
	uint16_t          tx_queue_back;
	struct mailbox    mb;
};

/* Configuration for the GK functional block. */
struct gk_config {
	/* Specify the size of the flow hash table. */
	unsigned int       flow_ht_size;

	/*
	 * DPDK LPM library implements the DIR-24-8 algorithm
	 * using two types of tables:
	 * (1) tbl24 is a table with 2^24 entries.
	 * (2) tbl8 is a table with 2^8 entries.
	 *
	 * To configure an LPM component instance, one needs to specify:
	 * @max_rules: the maximum number of rules to support.
	 * @number_tbl8s: the number of tbl8 tables.
	 *
	 * Here, it supports both IPv4 and IPv6 configuration.
	 */
	unsigned int       max_num_ipv4_rules;
	unsigned int       num_ipv4_tbl8s;
	unsigned int       max_num_ipv6_rules;
	unsigned int       num_ipv6_tbl8s;

	/* The maximum number of neighbor entries for the LPM FIB. */
	unsigned int       max_num_ipv6_neighbors;

	/*
	 * The IPv4 LPM reserves 24 bits for the next-hop field,
	 * whereas IPv6 LPM reserves 21 bits.
	 */
	unsigned int       gk_max_num_ipv4_fib_entries;
	unsigned int       gk_max_num_ipv6_fib_entries;

	/* Time for scanning the whole flow table in ms. */
	unsigned int       flow_table_full_scan_ms;

	/* Parameters to setup the mailbox instance. */
	unsigned int       mailbox_max_entries;
	unsigned int       mailbox_mem_cache_size;
	unsigned int       mailbox_burst_size;

	/*
	 * The fields below are for internal use.
	 * Configuration files should not refer to them.
	 */

	/* Timeout in cycles used to prune the expired request flow entries. */
	uint64_t           request_timeout_cycles;

	rte_atomic32_t     ref_cnt;

	/* The lcore ids at which each instance runs. */
	unsigned int       *lcores;

	/* The number of lcore ids in @lcores. */
	int                num_lcores;

	struct gk_instance *instances;
	struct net_config  *net;
	struct sol_config  *sol_conf;

	/*
	 * The LPM table used by the GK instances.
	 * We assume that all the GK instances are
	 * on the same numa node, so that only one global
	 * LPM table is maintained.
	 */
	struct gk_lpm      lpm_tbl;

	/* The RSS configuration for the front interface. */
	struct gatekeeper_rss_config rss_conf_front;

	/* The RSS configuration for the back interface. */
	struct gatekeeper_rss_config rss_conf_back;
};

/* Define the possible command operations for GK block. */
enum gk_cmd_op {
	GGU_POLICY_ADD,
	GK_SYNCH_WITH_LPM,
};

/*
 * XXX Structure for each command. Add new fields to support more commands.
 *
 * Notice that, the writers of a GK mailbox: the GK-GT unit and Dynamic config.
 */
struct gk_cmd_entry {
	enum gk_cmd_op  op;

	union {
		struct ggu_policy ggu;
		struct gk_fib *fib;
	} u;
};

struct gk_config *alloc_gk_conf(void);
void set_gk_request_timeout(unsigned int request_timeout_sec,
	struct gk_config *gk_conf);
int gk_conf_put(struct gk_config *gk_conf);
int run_gk(struct net_config *net_conf, struct gk_config *gk_conf,
	struct sol_config *sol_conf);
struct mailbox *get_responsible_gk_mailbox(
	const struct ip_flow *flow, const struct gk_config *gk_conf);

int pkt_copy_cached_eth_header(struct rte_mbuf *pkt,
	struct ether_cache *eth_cache, size_t l2_len_out);

static inline void
gk_conf_hold(struct gk_config *gk_conf)
{
	rte_atomic32_inc(&gk_conf->ref_cnt);
}

#endif /* _GATEKEEPER_GK_H_ */
