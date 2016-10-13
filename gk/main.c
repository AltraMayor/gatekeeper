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

#include <string.h>
#include <stdbool.h>

#include <rte_ip.h>
#include <rte_log.h>
#include <rte_hash.h>
#include <rte_thash.h>
#include <rte_lcore.h>
#include <rte_ethdev.h>
#include <rte_memcpy.h>
#include <rte_cycles.h>
#include <rte_malloc.h>

#include "gatekeeper_gk.h"
#include "gatekeeper_main.h"
#include "gatekeeper_net.h"

#define	START_PRIORITY		 (38)
/* Set @START_ALLOWANCE as the double size of a large DNS reply. */
#define	START_ALLOWANCE		 (8)

/* XXX Sample parameter for test only. */
#define GK_MAX_NUM_LCORES	 (16)

#define GATEKEEPER_MAX_PKT_BURST (32)

/*
 * A flow entry can be in one of three states:
 * request, granted, or declined.
 */
enum gk_flow_state { GK_REQUEST, GK_GRANTED, GK_DECLINED };

struct ip_flow {
	/* IPv4 or IPv6. */
	uint16_t proto;

	union {
		struct {
			uint32_t src;
			uint32_t dst;
		} v4;

		struct {
			uint8_t src[16];
			uint8_t dst[16];
		} v6;
	} f;
};

/* Store information about a packet. */
struct ipacket {
	struct ip_flow  flow;
	struct rte_mbuf *pkt;
};

struct flow_entry {
	/* IP flow information. */
	struct ip_flow flow;

	/* The state of the entry. */
	enum gk_flow_state state;

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
			/* 
			 * The ID of the Grantor server to which packets to
			 * @dst must be sent.
			 */
			int grantor_id;
		} request;

		struct {
			/* When the granted capability expires. */
			uint64_t cap_expire_at;
			/* When @budget_byte is reset. */
			uint64_t budget_renew_at;
			/* 
			 * When @budget_byte is reset, reset it to
			 * @tx_rate_kb_cycle * 1024 bytes.
			 */
			int tx_rate_kb_cycle;
			/* How many bytes @src can still send in current cycle. */
			int budget_byte;
			/*
			 * The ID of the Grantor server to which packets to
			 * @dst must be sent.
			 */
			int grantor_id;
			/* When GK should send the next renewal to @grantor_id. */
			uint64_t send_next_renewal_at;
			/*
			 * How many cycles (unit) GK must wait before
			 * sending the next capability renewal request.
			 */
			uint64_t renewal_step_cycle;
		} granted;

		struct {
			/*
			 * When the punishment (i.e. the declined capability)
			 * expires.
			 */
			uint64_t expire_at;
		} declined;
	} u;
};

/* To support the optimized implementation of generic RSS hash function. */
static uint8_t rss_key_be[RTE_DIM(default_rss_key)];

/*
 * Optimized generic implementation of RSS hash function.
 * If you want the calculated hash value matches NIC RSS value,
 * you have to use special converted key with rte_convert_rss_key() fn.
 * @param input_tuple
 *   Pointer to input tuple with network order.
 * @param input_len
 *   Length of input_tuple in 4-bytes chunks.
 * @param *rss_key
 *   Pointer to RSS hash key.
 * @return
 *   Calculated hash value.
 */
static inline uint32_t
gk_softrss_be(const uint32_t *input_tuple, uint32_t input_len,
		const uint8_t *rss_key)
{
	uint32_t i;
	uint32_t j;
	uint32_t ret = 0;

	for (j = 0; j < input_len; j++) {
		/*
		 * Need to use little endian,
		 * since it takes ordering as little endian in both bytes and bits.
		 */
		uint32_t val = rte_be_to_cpu_32(input_tuple[j]);
		for (i = 0; i < 32; i++)
			if (val & (1 << (31 - i)))
				ret ^= ((const uint32_t *)rss_key)[j] << i |
					((uint64_t)(((const uint32_t *)rss_key)[j + 1]) >> (32 - i));
	}

	return ret;
}

static uint32_t
rss_hash_func(const void *data, __attribute__((unused)) uint32_t data_len,
        __attribute__((unused)) uint32_t init_val)
{
	const struct ip_flow *flow = (const struct ip_flow *)data;

	if (flow->proto == ETHER_TYPE_IPv4)
		return gk_softrss_be((const uint32_t *)&flow->f,
				(sizeof(flow->f.v4)/sizeof(uint32_t)), rss_key_be);
	else if (flow->proto == ETHER_TYPE_IPv6)
		return gk_softrss_be((const uint32_t *)&flow->f,
				(sizeof(flow->f.v6)/sizeof(uint32_t)), rss_key_be);
	else
		RTE_ASSERT(false);

	return 0;
}

/* Type of function used to compare the hash key. */
static int
ip_flow_cmp_eq(const void *key1, const void *key2,
	__attribute__((unused)) size_t key_len)
{
	const struct ip_flow *f1 = (const struct ip_flow *)key1;
	const struct ip_flow *f2 = (const struct ip_flow *)key2;

	if (f1->proto != f2->proto)
		return f1->proto == ETHER_TYPE_IPv4 ? -1 : 1;

	if (f1->proto == ETHER_TYPE_IPv4)
		return memcmp(&f1->f.v4, &f2->f.v4, sizeof(f1->f.v4));
	else
		return memcmp(&f1->f.v6, &f2->f.v6, sizeof(f1->f.v6));
}

/* We should avoid calling integer_log_base_2() with zero. */
static inline uint8_t
integer_log_base_2(uint64_t delta_time)
{
#if __WORDSIZE == 64
    return (8 * sizeof(uint64_t) - 1) - __builtin_clzl(delta_time);
#else
    return (8 * sizeof(uint64_t) - 1) - __builtin_clzll(delta_time);
#endif
}

/* 
 * It converts the difference of time between the current packet and 
 * the last seen packet into a given priority. 
 */
static uint8_t 
priority_from_delta_time(uint64_t present, uint64_t past)
{
	uint64_t delta_time;

	if (unlikely(present < past)) {
		/*
		 * This should never happen, but we handle it gracefully here 
		 * in order to keep going.
		 */
		RTE_LOG(ERR, GATEKEEPER,
			"gk: the present time smaller than the past time!\n");

		return 0;
	}

	delta_time = (present - past) * picosec_per_cycle;
	if (unlikely(delta_time < 1))
		return 0;
	
	return integer_log_base_2(delta_time);
}

static void
extract_packet_info(struct rte_mbuf *pkt, struct ipacket *packet)
{
	uint16_t ether_type;
	struct ether_hdr *eth_hdr;
	struct ipv4_hdr  *ip4_hdr;
	struct ipv6_hdr  *ip6_hdr;

	eth_hdr = rte_pktmbuf_mtod(pkt, struct ether_hdr *);
	ether_type = rte_be_to_cpu_16(eth_hdr->ether_type);

	switch (ether_type) {
	case ETHER_TYPE_IPv4:
		ip4_hdr = rte_pktmbuf_mtod_offset(pkt, 
					struct ipv4_hdr *, 
					sizeof(struct ether_hdr));
		packet->flow.proto = ETHER_TYPE_IPv4;
		packet->flow.f.v4.src = ip4_hdr->src_addr;
		packet->flow.f.v4.dst = ip4_hdr->dst_addr;
		break;

	case ETHER_TYPE_IPv6:
		ip6_hdr = rte_pktmbuf_mtod_offset(pkt, 
					struct ipv6_hdr *, 
					sizeof(struct ether_hdr));
		packet->flow.proto = ETHER_TYPE_IPv6;
		rte_memcpy(packet->flow.f.v6.src, ip6_hdr->src_addr,
			sizeof(packet->flow.f.v6.src));
		rte_memcpy(packet->flow.f.v6.dst, ip6_hdr->dst_addr,
			sizeof(packet->flow.f.v6.dst));
		break;

	default:
		packet->flow.proto = 0;
		RTE_LOG(NOTICE, GATEKEEPER,
			"gk: unknown network layer protocol %" PRIu16 "!\n",
			ether_type);
		break;
	}
}

static inline void
initialize_flow_entry(struct flow_entry *fe, struct ip_flow *flow)
{
	rte_memcpy(&fe->flow, flow, sizeof(*flow));

	fe->state = GK_REQUEST;
	fe->u.request.last_packet_seen_at = rte_rdtsc();
	fe->u.request.last_priority = START_PRIORITY;
	fe->u.request.allowance = START_ALLOWANCE - 1;
	/* TODO Grantor ID comes from LPM lookup. */
	fe->u.request.grantor_id = 0;
}

static inline void
reinitialize_flow_entry(struct flow_entry *fe, uint64_t now)
{
	fe->state = GK_REQUEST;
	fe->u.request.last_packet_seen_at = now;
	fe->u.request.last_priority = START_PRIORITY;
	fe->u.request.allowance = START_ALLOWANCE - 1;
}

static inline int
drop_packet(struct rte_mbuf *pkt)
{
	rte_pktmbuf_free(pkt);
	return 0;
}

/* 
 * When a flow entry is at request state, all the GK block processing
 * that entry does is to:
 * (1) compute the priority of the packet.
 * (2) encapsulate the packet as a request.
 * (3) put this encapsulated packet in the request queue.
 */
static int
gk_process_request(struct flow_entry *fe,
	 __attribute__((unused)) struct ipacket *packet)
{
	uint64_t now = rte_rdtsc();
	uint8_t priority = priority_from_delta_time(now,
			fe->u.request.last_packet_seen_at);

	fe->u.request.last_packet_seen_at = now;

	/*
	 * The reason for using "<" instead of "<=" is that the equal case 
	 * means that the source has waited enough time to have the same 
	 * last priority, so it should be awarded with the allowance.
	 */
	if (priority < fe->u.request.last_priority &&
			fe->u.request.allowance > 0) {
		fe->u.request.allowance--;
		priority = fe->u.request.last_priority;
	} else {
		fe->u.request.last_priority = priority;
		fe->u.request.allowance = START_ALLOWANCE - 1;
	}

	/*
	 * Adjust @priority for the DSCP field.
	 * DSCP 0 for legacy packets; 1 for granted packets; 
	 * 2 for capability renew; 3-63 for requests.
	 */
	priority += 3;
	if (unlikely(priority > 63))
		priority = 63;

	/* The assigned priority is @priority. */
	
	/* TODO Encapsulate the packet as a request. */

	/* TODO Put this encapsulated packet in the request queue. */

	return 0;
}

static inline uint64_t
cycle_from_second(uint64_t time)
{
	return (cycles_per_sec * time);
}

static int
gk_process_granted(struct flow_entry *fe, struct ipacket *packet)
{
	bool renew_cap;
	uint64_t now = rte_rdtsc();
	struct rte_mbuf *pkt = packet->pkt;

	if (now >= fe->u.granted.cap_expire_at) {
		reinitialize_flow_entry(fe, now);
		return gk_process_request(fe, packet);
	}

	if (now >= fe->u.granted.budget_renew_at) {
		fe->u.granted.budget_renew_at = now + cycle_from_second(1);
		fe->u.granted.budget_byte = fe->u.granted.tx_rate_kb_cycle * 1024;
	}

	if (pkt->data_len > fe->u.granted.budget_byte)
		return drop_packet(pkt);

	fe->u.granted.budget_byte -= pkt->data_len;
	renew_cap = now >= fe->u.granted.send_next_renewal_at;
	if (renew_cap)
		fe->u.granted.send_next_renewal_at = now +
			fe->u.granted.renewal_step_cycle;

	/*
	 * TODO Encapsulate packet as a granted packet,
	 * mark it as a capability renewal request if @renew_cap is true,
	 * enter destination according to @fe->u.granted.grantor_id,
	 * and put the encapsulated packet in the granted queue.
	 */

	return 0;
}

static int
gk_process_declined(struct flow_entry *fe, struct ipacket *packet)
{
	uint64_t now = rte_rdtsc();

	if (unlikely(now >= fe->u.declined.expire_at)) {
		reinitialize_flow_entry(fe, now);
		return gk_process_request(fe, packet);
	}

	return drop_packet(packet->pkt);
}

static int
setup_gk_instance(unsigned int lcore_id, struct gk_config *gk_conf)
{
	int  ret;
	char ht_name[64];
	unsigned int block_idx = lcore_id - gk_conf->lcore_start_id;

	struct gk_instance *instance = &gk_conf->instances[block_idx];
	struct rte_hash_parameters ip_flow_hash_params = {
		.entries = gk_conf->flow_ht_size,
		.key_len = sizeof(struct ip_flow),
		.hash_func = rss_hash_func,
		.hash_func_init_val = 0,
	};

	ret = snprintf(ht_name, sizeof(ht_name), "ip_flow_hash_%u", block_idx);
	RTE_ASSERT(ret < sizeof(ht_name));

	/* Setup the flow hash table for GK block @block_idx. */
	ip_flow_hash_params.name = ht_name;
	ip_flow_hash_params.socket_id = rte_lcore_to_socket_id(lcore_id);
	instance->ip_flow_hash_table = rte_hash_create(&ip_flow_hash_params);
	if (!instance->ip_flow_hash_table) {
		RTE_LOG(ERR, HASH,
			"The GK block cannot create hash table at lcore %u!\n",
			lcore_id);

		ret = -1;
		goto out;
	}
	/* Set a new hash compare function other than the default one. */
	rte_hash_set_cmp_func(instance->ip_flow_hash_table, ip_flow_cmp_eq);

	/* Setup the flow entry table for GK block @block_idx. */
	instance->ip_flow_entry_table = (struct flow_entry *)rte_calloc(NULL,
		gk_conf->flow_ht_size, sizeof(struct flow_entry), 0);
	if (!instance->ip_flow_entry_table) {
		RTE_LOG(ERR, MALLOC,
			"The GK block can't create flow entry table at lcore %u!\n",
			lcore_id);

		ret = -1;
		goto flow_hash;
	}

	ret = 0;
	goto out;

flow_hash:
	rte_hash_free(instance->ip_flow_hash_table);
	instance->ip_flow_hash_table = NULL;
out:
	return ret;
}

static int
gk_proc(void *arg)
{
	/* TODO Implement the basic algorithm of a GK block. */

	unsigned int block_idx;
	unsigned int lcore = rte_lcore_id();
	struct gk_instance *instance;
	struct gk_config   *gk_conf = (struct gk_config *)arg;
	block_idx = lcore - gk_conf->lcore_start_id;

	uint8_t port_in = get_net_conf()->front.id;
	uint8_t port_out = get_net_conf()->back.id;
	uint16_t rx_queue = (uint16_t)lcore;
	uint16_t tx_queue = (uint16_t)lcore;

	RTE_LOG(NOTICE, GATEKEEPER,
		"gk: the GK block is running at lcore = %u\n", lcore);

	rte_atomic32_inc(&gk_conf->ref_cnt);

	instance = &gk_conf->instances[block_idx];

	while (likely(!exiting)) {
		/* 
		 * XXX Sample setting for test only.
		 * 
		 * Here, just use one queue (0) for test.
		 *
		 * Queue identifiers should be changed 
		 * according to configuration.
		 */

		/* Get burst of RX packets, from first port of pair. */
		int i;
		int ret = -1;
		uint16_t num_rx;
		uint16_t num_tx = 0;
		uint16_t num_tx_succ;
		struct rte_mbuf *rx_bufs[GATEKEEPER_MAX_PKT_BURST];
		struct rte_mbuf *tx_bufs[GATEKEEPER_MAX_PKT_BURST];

		/* Load a set of packets from the front NIC. */
		num_rx = rte_eth_rx_burst(port_in, rx_queue, rx_bufs,
			GATEKEEPER_MAX_PKT_BURST);

		if (unlikely(num_rx == 0))
			continue;

		for (i = 0; i < num_rx; i++) {
			struct ipacket packet;
			/*
			 * Pointer to the flow entry in request state 
			 * under evaluation.
			 */
			struct flow_entry *fe;
			struct rte_mbuf *pkt = rx_bufs[i];
			
			extract_packet_info(pkt, &packet);

			/* 
			 * Find the flow entry for the IP pair.
			 * Create a new flow entry if not found.
			 */
			ret = rte_hash_lookup_with_hash(instance->ip_flow_hash_table,
				&packet.flow, pkt->hash.rss);
			if (ret < 0) {
				/* Create a new flow entry. */
				ret = rte_hash_add_key_with_hash(instance->ip_flow_hash_table,
 					(void *)&packet.flow, pkt->hash.rss);
				if (ret < 0) {
					RTE_LOG(ERR, HASH,
						"The GK block failed to add new key to hash table!\n");
					rte_pktmbuf_free(pkt);
					continue;
				}

				fe = &instance->ip_flow_entry_table[ret];
				initialize_flow_entry(fe, &packet.flow);
			} else
				fe = &instance->ip_flow_entry_table[ret];

			/*
			 * 1.1 If the pair of source and destination addresses 
			 * is in the flow table, proceed as the entry instructs,
			 * and go to the next packet.
			 */
			switch(fe->state) {
			case GK_REQUEST:
				ret = gk_process_request(fe, &packet);
				break;

			case GK_GRANTED:
				ret = gk_process_granted(fe, &packet);
				break;

			case GK_DECLINED:
				ret = gk_process_declined(fe, &packet);
				break;

			default:
				ret = -1;
				/* XXX Incorrect state, log warning. */
				RTE_LOG(ERR, GATEKEEPER,
					"gk: unknown flow state!\n");
				break;
			}

			if (ret < 0)
				rte_pktmbuf_free(pkt);
			else
				tx_bufs[num_tx++] = pkt;

			/*
			 * TODO 1.2 Otherwise, look up the destination address
			 * in the global LPM table.
			 *
			 * 1.2.1 If there is an entry for the destination and 
			 * the entry instructs to enforce policies over its packets,
 			 * initialize an entry in the flow table, proceed as the 
			 * brand-new entry instructs, and go to the next packet.
			 *
			 * 1.2.2 If there is an entry for the destination and
			 * the entry instructs to forward its packets to the
			 * back interface, forward accordingly.
			 *
			 * 1.2.3 Otherwise, drop the packet.
			 */
		}

		/* Send burst of TX packets, to second port of pair. */
		num_tx_succ = rte_eth_tx_burst(port_out, tx_queue, tx_bufs, num_tx);

		/* XXX Do something better here! For now, free any unsent packets. */
		if (unlikely(num_tx_succ < num_tx)) {
			for (i = num_tx_succ; i < num_tx; i++)
				rte_pktmbuf_free(tx_bufs[i]);
		}

		/* 
		 * TODO Implement the command processing as follows:
		 * Load a set of commands from its mailbox ring, and 
		 * process each command.
		 *
		 * The writers of a GK mailbox: the GK-GT unit and Dynamic config.
		 */
	}

	RTE_LOG(NOTICE, GATEKEEPER,
		"gk: the GK block at lcore = %u is exiting\n", lcore);

	return cleanup_gk(gk_conf);
}

struct gk_config *
alloc_gk_conf(void)
{
	return rte_calloc("gk_config", 1, sizeof(struct gk_config), 0);
}

int
run_gk(struct gk_config *gk_conf)
{
	/* TODO Initialize and run GK functional block. */

	unsigned int i;
	unsigned int num_lcores;
	int ret;
	uint8_t port_in = get_net_conf()->front.id;
	uint16_t gk_queues[GK_MAX_NUM_LCORES];
	struct gk_instance *inst_ptr;

	if (!gk_conf) {
		ret = -1;
		goto out;
	}

	num_lcores = gk_conf->lcore_end_id - gk_conf->lcore_start_id + 1;
	RTE_ASSERT(num_lcores <= GK_MAX_NUM_LCORES);
	for (i = 0; i < num_lcores; i++) {
		gk_queues[i] = i + gk_conf->lcore_start_id;
	}

	ret = gatekeeper_setup_rss(port_in, gk_queues, num_lcores);
	if (ret < 0)
		goto out;

	/* Convert RSS key. */
	rte_convert_rss_key((uint32_t *)&default_rss_key,
		(uint32_t *)rss_key_be, RTE_DIM(default_rss_key));

	gk_conf->instances = (struct gk_instance *)rte_calloc(NULL,
		num_lcores, sizeof(struct gk_instance), 0);
	if (!gk_conf->instances) {
		ret = -1;
		goto out;
	}

	for (i = gk_conf->lcore_start_id; i <= gk_conf->lcore_end_id; i++) {
		/* Setup the gk instance for lcore @i. */
		ret = setup_gk_instance(i, gk_conf);
		if (ret < 0) {
			RTE_LOG(ERR, GATEKEEPER, 
				"gk: failed to setup gk instances for GK block at %u!\n",
				i);
			goto setup;
		}

		ret = rte_eal_remote_launch(gk_proc, gk_conf, i);
		if (ret) {
			RTE_LOG(ERR, EAL, "lcore %u failed to launch GK\n", i);
			ret = -1;
			goto instance;
		}
	}

	goto out;

instance:
	/* GK instance at lcore @i failed to launch. */
	inst_ptr = &gk_conf->instances[i - gk_conf->lcore_start_id];
	
	rte_hash_free(inst_ptr->ip_flow_hash_table);
	inst_ptr->ip_flow_hash_table = NULL;
	
	rte_free(inst_ptr->ip_flow_entry_table);
	inst_ptr->ip_flow_entry_table = NULL;
setup:
	/*
	 * If failed to setup the first gk instance, needs to release
	 * 'gk_conf->instances' and 'gk_conf'.
	 * Otherwise, the launched gk instances need to call cleanup_gk() to release.
	 */
	if (i == gk_conf->lcore_start_id) {
		rte_free(gk_conf->instances);
		gk_conf->instances = NULL;

		rte_free(gk_conf);
		gk_conf = NULL;
	}
out:
	return ret;
}

int
cleanup_gk(struct gk_config *gk_conf)
{
	unsigned int i;
	unsigned int num_lcores = gk_conf->lcore_end_id - gk_conf->lcore_start_id + 1;
	/*
	 * Atomically decrements the atomic counter (v) by one and returns true 
	 * if the result is 0, or false in all other cases.
	 */
	if (rte_atomic32_dec_and_test(&gk_conf->ref_cnt)) {
		for (i = 0; i < num_lcores; i++) {
			if (gk_conf->instances[i].ip_flow_hash_table)
				rte_hash_free(gk_conf->instances[i].ip_flow_hash_table);

			if (gk_conf->instances[i].ip_flow_entry_table)
				rte_free(gk_conf->instances[i].ip_flow_entry_table);
		}

		rte_free(gk_conf->instances);
		rte_free(gk_conf);
	}

	return 0;
}
