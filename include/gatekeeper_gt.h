/*
 * Gatekeeper - DDoS protection system.
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

#define CTYPE_STRUCT_GT_CONFIG_PTR "struct gt_config *"

struct gt_packet_headers {
	uint16_t outer_ethertype;
	uint16_t inner_ip_ver;
	uint8_t  l4_proto;
	uint8_t  priority;
	uint8_t  outer_ecn;
	/* Length of packet after IP headers (L4 + L5 + payload). */
	uint16_t upper_len;

	void     *l2_hdr;
	void     *outer_l3_hdr;
	void     *inner_l3_hdr;
	void     *l4_hdr;

	/* Field indicating whether the associated packet is fragmented. */
	bool     frag;

	/*
	 * The fields below are for internal use.
	 * Configuration files should not refer to them.
	 */

	/* Fields for parsing fragmented packets. */
	uint32_t l2_outer_l3_len;
	uint32_t inner_l3_len;
	struct ipv6_extension_fragment *frag_hdr;
};

/*
 * Data for building policy decision notification packets for
 * Gatekeeper servers seen by GT block instances.
 */
struct ggu_notify_pkt {
	/* The IP address of the Gatekeeper server. */
	struct ipaddr   ipaddr;

	/*
	 * The notification packet of policy decisions
	 * being built to send to this Gatekeeper server.
	 */
	struct rte_mbuf *buf;
};

/* Structures for each GT instance. */
struct gt_instance {
	/* RX queue on the front interface. */
	uint16_t  rx_queue;

	/* TX queue on the front interface. */
	uint16_t  tx_queue;

	/* The lua state that belongs to the instance. */
	lua_State *lua_state;

	/* The neighbor hash tables that stores the Ethernet cached headers. */
	struct neighbor_hash_table neigh;
	struct neighbor_hash_table neigh6;

	/*
	 * The fragment table maintains information about already
	 * received fragments of the packet.
	 */
	struct rte_ip_frag_tbl *frag_tbl;

	/*
	 * Fixed array of packet buffers for policy decision
	 * notification packets for the last @max_ggu_pkts
	 * Gatekeeper servers seen by this GT block instance.
	 */
	struct ggu_notify_pkt *ggu_pkts;

	/* The number of valid entries in @ggu_pkts. */
	unsigned int          num_ggu_pkts;

	struct mailbox        mb;

	/* The packet mbuf pool for the GT instance. */
	struct rte_mempool    *mp;
} __rte_cache_aligned;

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

	/* The maximum number of packets to retrieve/transmit. */
	uint16_t           max_pkt_burst;

	/*
	 * Number of iterations of packets processed by each GT
	 * block before flushing all policy decision notification
	 * packets. Set to 1 to flush after every RX iteration.
	 */
	unsigned int       batch_interval;

	/*
	 * Maximum number of Gatekeeper servers for which to
	 * keep policy decision notification packet buffers.
	 */
	unsigned int       max_ggu_notify_pkts;

	/* Parameters to setup the mailbox instance. */
	unsigned int       mailbox_max_entries_exp;
	unsigned int       mailbox_mem_cache_size;
	unsigned int       mailbox_burst_size;

	/* Log level for GT block. */
	uint32_t           log_level;
	/* Log ratelimit interval in ms for GT block. */
	uint32_t           log_ratelimit_interval_ms;
	/* Log ratelimit burst size for GT block. */
	uint32_t           log_ratelimit_burst;

	/*
	 * An option to disable packet reassembling
	 * at Grantor servers.
	 */
	bool               reassembling_enabled;

	/*
	 * The fields below are for internal use.
	 * Configuration files should not refer to them.
	 */

	/* Base directory of the Lua policies. */
	char               *lua_base_directory;

	/* Lua policy configuration file for Grantor. */
	char               *lua_policy_file;

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

/* Define the possible command operations for GT block. */
enum gt_cmd_op {
	GT_UPDATE_POLICY,
	GT_UPDATE_POLICY_INCREMENTALLY,
};

/* Currently, the Dynamic config is the only writer of GT mailboxes. */
struct gt_cmd_entry {
	enum gt_cmd_op  op;

	union {
		lua_State *lua_state; /* GT_UPDATE_POLICY */
		/* GT_UPDATE_POLICY_INCREMENTALLY */
		struct {
			size_t len;
			char *lua_bytecode;
			int is_returned;
		} bc;
	} u;
};

struct gt_config *alloc_gt_conf(void);
int gt_conf_put(struct gt_config *gt_conf);
int run_gt(struct net_config *net_conf, struct gt_config *gt_conf,
	const char *lua_base_directory, const char *lua_policy_file);
int l_update_gt_lua_states(lua_State *l);

static inline void
gt_conf_hold(struct gt_config *gt_conf)
{
	rte_atomic32_inc(&gt_conf->ref_cnt);
}

/*
 * Key in the registry of a Lua state used to run policies that points to
 * the lcore_id where the policy runs.
 */
#define GT_LUA_LCORE_ID_NAME "lcore_id"

#endif /* _GATEKEEPER_GT_H_ */
