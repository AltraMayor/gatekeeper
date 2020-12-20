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
#include <rte_bpf.h>

#include "gatekeeper_fib.h"
#include "gatekeeper_net.h"
#include "gatekeeper_ipip.h"
#include "gatekeeper_ggu.h"
#include "gatekeeper_mailbox.h"
#include "gatekeeper_lpm.h"
#include "gatekeeper_sol.h"
#include "gatekeeper_ratelimit.h"
#include "gatekeeper_log_ratelimit.h"

extern int gk_logtype;

#define GK_LOG(level, ...)                               \
	rte_log_ratelimit(RTE_LOG_ ## level, gk_logtype, \
		"GATEKEEPER GK: " __VA_ARGS__)

/* Store information about a packet. */
struct ipacket {
	/* Flow identifier for this packet. */
	struct ip_flow  flow;
	/* Pointer to the packet itself. */
	struct rte_mbuf *pkt;
	/*
	 * Pointer to the l3 header.
	 *
	 * NOTICE
	 *    extract_packet_info() only guarantees
	 *    the length of the L3 header without extensions.
	 */
	void *l3_hdr;
};

/* Structure for the GK basic measurements. */
struct gk_measurement_metrics {
	/* Total number of packets received. */
	uint64_t tot_pkts_num;
	/* Total size in bytes of packets received. */
	uint64_t tot_pkts_size;
	/* Number of packets forwarded through the granted channel. */
	uint64_t pkts_num_granted;
	/* Size in bytes of packets forwarded through the granted channel. */
	uint64_t pkts_size_granted;
	/* Number of packets forwarded through the request channel. */
	uint64_t pkts_num_request;
	/* Size in bytes of packets forwarded through the request channel. */
	uint64_t pkts_size_request;
	/*
	 * Number of packets dropped because it has been rejected due to
	 * a policy decision. While all packets of flows in declined state are
	 * counted here, packets of flows in granted state may be counted here
	 * too when these packets exceed the allocated bandwidth.
	 */
	uint64_t pkts_num_declined;
	/* Size in bytes of packets dropped because it has been rejected. */
	uint64_t pkts_size_declined;
	/*
	 * Total number of packets dropped.
	 * Declined packets are counted here as well.
	 */
	uint64_t tot_pkts_num_dropped;
	/* Total size in bytes of packets dropped. */
	uint64_t tot_pkts_size_dropped;
	/*
	 * Total number of packets distributed to other blocks.
	 * It includes ARP packets handled to the LLS block,
	 * and packets handed off to the IPv4 and IPv6 ACLs.
	 */
	uint64_t tot_pkts_num_distributed;
	/* Total size in bytes of packets distributed to other blocks. */
	uint64_t tot_pkts_size_distributed;
};

/* Structures for each GK instance. */
struct gk_instance {
	struct rte_hash   *ip_flow_hash_table;
	struct flow_entry *ip_flow_entry_table;
	/* RX queue on the front interface. */
	uint16_t          rx_queue_front;
	/* TX queue on the front interface. */
	uint16_t          tx_queue_front;
	/* RX queue on the back interface. */
	uint16_t          rx_queue_back;
	/* TX queue on the back interface. */
	uint16_t          tx_queue_back;
	struct mailbox    mb;
	/* Data structure used for the GK basic measurements. */
	struct gk_measurement_metrics traffic_stats;
	/* Data structures used to limit the rate of icmp messages. */
	struct token_bucket_ratelimit_state front_icmp_rs;
	struct token_bucket_ratelimit_state back_icmp_rs;
	unsigned int num_scan_del;
	/*
	 * The memory pool used for packet buffers in this instance.
	 */
	struct rte_mempool *mp;
	struct sol_instance *sol_inst;
} __rte_cache_aligned;

#define GK_MAX_BPF_FLOW_HANDLERS	(UINT8_MAX + 1)

typedef uint64_t (*rte_bpf_jitted_func_t)(void *);

struct gk_bpf_flow_handler {
	/* Required program to initialize cookies. */
	struct rte_bpf *f_init;
	rte_bpf_jitted_func_t f_init_jit;
	/* Required program to decide the fate of a packet. */
	struct rte_bpf *f_pkt;
	rte_bpf_jitted_func_t f_pkt_jit;
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
	 * @max_rules: the maximum number of rules to support. Note that the maximum
	 * number of LPM FIB entries should be equal to the maximum number of rules.
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
	 * Number of iterations of the GK block's main loop
	 * between scanning entries of the flow table. Set to
	 * 0 to scan an entry every iteration of the loop.
	 */
	unsigned int       flow_table_scan_iter;

	/*
	 * When the flow hash table is full, Gatekeeper will
	 * enable the insertion again only after cleaning up
	 * a number of expired flow entries.
	 */
	unsigned int       scan_del_thresh;

	/* The maximum number of packets to retrieve/transmit. */
	uint16_t           front_max_pkt_burst;
	uint16_t           back_max_pkt_burst;

	/* The rate and burst size of the icmp messages. */
	uint32_t           front_icmp_msgs_per_sec;
	uint32_t           front_icmp_msgs_burst;
	uint32_t           back_icmp_msgs_per_sec;
	uint32_t           back_icmp_msgs_burst;

	/* Parameters to setup the mailbox instance. */
	unsigned int       mailbox_max_entries_exp;
	unsigned int       mailbox_mem_cache_size;
	unsigned int       mailbox_burst_size;

	/* Log level for GK block. */
	uint32_t           log_level;
	/* Dynamic logging type, assigned at runtime. */
	int                log_type;
	/* Log ratelimit interval in ms for GK block. */
	uint32_t           log_ratelimit_interval_ms;
	/* Log ratelimit burst size for GK block. */
	uint32_t           log_ratelimit_burst;

	/* Time for logging the basic measurements in ms. */
	unsigned int       basic_measurement_logging_ms;

	/*
	 * The fields below are for internal use.
	 * Configuration files should not refer to them.
	 */

	rte_atomic32_t     ref_cnt;

	/* The lcore ids at which each instance runs. */
	unsigned int       *lcores;

	/* Mapping the GK instances to the SOL instances. */
	unsigned int       *gk_sol_map;

	/* The number of lcore ids in @lcores. */
	int                num_lcores;

	/*
	 * Array that maps a front interface
	 * RX queue ID to the associated GK
	 * instance index. Queue IDs not
	 * associated to a GK instance return -1.
	 */
	int                *queue_id_to_instance;

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

	/* BPF programs available for policies to associate to flow entries. */
	struct gk_bpf_flow_handler flow_handlers[GK_MAX_BPF_FLOW_HANDLERS];
};

/* A flow entry can be in one of the following states: */
enum { GK_REQUEST, GK_GRANTED, GK_DECLINED, GK_BPF };

struct flow_entry {
	/* IP flow information. */
	struct ip_flow flow;

	/* RSS hash value of the IP flow. */
	uint32_t flow_hash_val;

	/* The state of the entry. */
	uint8_t state;

	/* Whether this entry is currently in use in ip_flow_entry_table. */
	bool    in_use;

	/*
	 * This field was moved from u.bpf.program_index below to solve the
	 * structure padding issue that prevents us from adding new fields.
	 *
	 * More specifically, before this move, the sizeof(struct flow_entry)
	 * is 128, so we cannot add new fields due to the compilation check
	 * in gk/main.c (i.e., RTE_BUILD_BUG_ON(sizeof(*fe) > 128)).
	 *
	 * Index of the BPF program associated to the GK_BPF state.
	 */
	uint8_t	 program_index;

	/*
	 * The fib entry that instructs where
	 * to send the packets for this flow entry.
	 */
	struct gk_fib *grantor_fib;

	/*
	 * The time at which this flow entry expires (in cycles).
	 */
	uint64_t expire_at;

	union {
		struct {
			/* The time the last packet of the entry was seen. */
			uint64_t last_packet_seen_at;
			/*
			 * The priority associated to
			 * the last packet of the entry.
			 */
			uint8_t last_priority;
			/*
			 * The number of packets that the entry is allowed
			 * to send with @last_priority without waiting
			 * the amount of time necessary to be granted
			 * @last_priority.
			 */
			uint8_t allowance;
		} request;

		struct {
			/* When @budget_byte is reset. */
			uint64_t budget_renew_at;
			/*
			 * When @budget_byte is reset, reset it to
			 * @tx_rate_kib_cycle * 1024 bytes.
			 */
			uint32_t tx_rate_kib_cycle;
			/*
			 * How many bytes @src can still send in current cycle.
			 */
			uint64_t budget_byte;
			/*
			 * When GK should send the next renewal to
			 * the corresponding grantor.
			 */
			uint64_t send_next_renewal_at;
			/*
			 * How many cycles (unit) GK must wait before
			 * sending the next capability renewal request.
			 */
			uint64_t renewal_step_cycle;
		} granted;

		struct {
			/*
			 * Memory to be passed to the BPF proram each time
			 * it is executed.
			 */
			struct gk_bpf_cookie cookie;
		} bpf;
	} u;
};

/* Define the possible command operations for GK block. */
enum gk_cmd_op {
	GK_ADD_POLICY_DECISION,
	GK_SYNCH_WITH_LPM,
	GK_FLUSH_FLOW_TABLE,
	GK_LOG_FLOW_STATE,
	GK_CMD_OP_MAX,
};

struct gk_add_policy {
	struct ggu_policy policy;
	uint32_t flow_hash_val;
};

struct gk_synch_request {
	struct gk_fib *fib;
	int update_only;
};

struct gk_flush_request {
	struct ip_prefix src;
	struct ip_prefix dst;
};

struct gk_log_flow {
	struct ip_flow flow;
	uint32_t flow_hash_val;
};

/*
 * Structure for each command.
 *
 * Notice that, the writers of a GK mailbox: the GK-GT unit and Dynamic config.
 */
struct gk_cmd_entry {
	enum gk_cmd_op  op;

	union {
		/* GGU policy to be added with GK_ADD_POLICY_DECISION op. */
		struct gk_add_policy ggu;
		/* FIB entry to synchronize with GK_SYNCH_WITH_LPM op. */
		struct gk_synch_request synch;
		/* Flow table flush request with GK_FLUSH_FLOW_TABLE op. */
		struct gk_flush_request flush;
		/* Flow state logging request with GK_LOG_FLOW_STATE op. */
		struct gk_log_flow log;
	} u;
};

struct gk_config *alloc_gk_conf(void);
int gk_conf_put(struct gk_config *gk_conf);
int run_gk(struct net_config *net_conf, struct gk_config *gk_conf,
	struct sol_config *sol_conf);
struct mailbox *get_responsible_gk_mailbox(
	uint32_t flow_hash_val, const struct gk_config *gk_conf);

int gk_flush_flow_table(const char *src_prefix,
	const char *dst_prefix, struct gk_config *gk_conf);
int gk_log_flow_state(const char *src_addr,
	const char *dst_addr, struct gk_config *gk_conf);

int pkt_copy_cached_eth_header(struct rte_mbuf *pkt,
	struct ether_cache *eth_cache, size_t l2_len_out);

static inline void
gk_conf_hold(struct gk_config *gk_conf)
{
	rte_atomic32_inc(&gk_conf->ref_cnt);
}

int gk_init_bpf_cookie(const struct gk_config *gk_conf, uint8_t program_index,
	struct gk_bpf_cookie *cookie);

static inline struct grantor_entry *
choose_grantor_per_flow(struct flow_entry *fe)
{
	return &fe->grantor_fib->u.grantor.set->entries[
		fe->flow_hash_val % fe->grantor_fib->u.grantor.set->num_entries
	];
}

#endif /* _GATEKEEPER_GK_H_ */
