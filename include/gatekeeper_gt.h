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

#ifndef _GATEKEEPER_GT_H_
#define _GATEKEEPER_GT_H_

#include <stdint.h>

#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_atomic.h>
#include <rte_ip_frag.h>

#include "gatekeeper_fib.h"
#include "gatekeeper_config.h"

struct gt_packet_headers {
	uint16_t outer_ethertype;
	uint16_t inner_ip_ver;
	uint8_t  l4_proto;
	uint8_t  priority;
	uint8_t  outer_ecn;

	void     *l2_hdr;
	void     *outer_l3_hdr;
	void     *inner_l3_hdr;
	void     *l4_hdr;

	/*
	 * The fields below are for internal use.
	 * Configuration files should not refer to them.
	 */

	/* Fields for parsing fragmented packets. */
	bool     frag;
	uint32_t l2_outer_l3_len;
	uint32_t inner_l3_len;
	struct ipv6_extension_fragment *frag_hdr;
};

/* Structures for each GT instance. */
struct gt_instance {
	/* RX queue on the front interface. */
	uint16_t      rx_queue;

	/* TX queue on the front interface. */
	uint16_t      tx_queue;

	/* The lua state that belongs to the instance. */
	lua_State     *lua_state;

	/* The neighbor hash tables that stores the Ethernet cached headers. */
	struct neighbor_hash_table neigh;
	struct neighbor_hash_table neigh6;

	/*
	 * The fragment table maintains information about already
	 * received fragments of the packet.
	 */
	struct rte_ip_frag_tbl *frag_tbl;
};

/* Configuration for the GT functional block. */
struct gt_config {
	/* The UDP source and destination port numbers for GK-GT Unit. */
	uint16_t           ggu_src_port;
	uint16_t           ggu_dst_port;

	/* The maximum number of neighbor entries for the GT. */
	int                max_num_ipv6_neighbors;

	/* Timeout for scanning the fragmentation table in ms. */
	uint32_t           frag_scan_timeout_ms;

	/* Number of buckets in the fragmentation table. */
	uint32_t           frag_bucket_num;

	/* Number of entries per bucket. It should be a power of two. */
	uint32_t           frag_bucket_entries;

	/*
	 * Maximum number of entries that could be stored in
	 * the fragmentation table.
	 */
	uint32_t           frag_max_entries;

	/* Maximum TTL numbers are in ms. */
	uint32_t           frag_max_flow_ttl_ms;

	/*
	 * The fields below are for internal use.
	 * Configuration files should not refer to them.
	 */
	rte_atomic32_t	   ref_cnt;

	/* The lcore ids at which each instance runs. */
	unsigned int       *lcores;

	/* The number of lcore ids in @lcores. */
	int                num_lcores;

	/* The network interface configuration. */
	struct net_config  *net;

	/* The gt instances. */
	struct gt_instance *instances;
};

struct gt_config *alloc_gt_conf(void);
int gt_conf_put(struct gt_config *gt_conf);
int run_gt(struct net_config *net_conf, struct gt_config *gt_conf);

static inline void
gt_conf_hold(struct gt_config *gt_conf)
{
	rte_atomic32_inc(&gt_conf->ref_cnt);
}

#endif /* _GATEKEEPER_GT_H_ */
