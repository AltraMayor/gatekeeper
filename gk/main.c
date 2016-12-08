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
#include <rte_lcore.h>
#include <rte_ethdev.h>
#include <rte_memcpy.h>
#include <rte_cycles.h>
#include <rte_malloc.h>

#include "gatekeeper_gk.h"
#include "gatekeeper_main.h"
#include "gatekeeper_net.h"
#include "gatekeeper_mailbox.h"
#include "gatekeeper_ipip.h"
#include "gatekeeper_config.h"

#define	START_PRIORITY		 (38)
/* Set @START_ALLOWANCE as the double size of a large DNS reply. */
#define	START_ALLOWANCE		 (8)

/*
 * Priority used for DSCP field of encapsulated packets:
 *  0 for legacy packets; 1 for granted packets; 
 *  2 for capability renew; 3-63 for request packets.
 */
#define PRIORITY_GRANTED	 (1)
#define PRIORITY_RENEW_CAP	 (2)
#define PRIORITY_MAX		 (63)

/* XXX Sample parameter for test only. */
#define GK_MAX_NUM_LCORES	 (16)

/* XXX Sample parameters, need to be tested for better performance. */
#define GK_CMD_BURST_SIZE        (32)

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

static int
extract_packet_info(struct rte_mbuf *pkt, struct ipacket *packet)
{
	int ret = 0;
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
		ret = -1;
		break;
	}

	packet->pkt = pkt;

	return ret;
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
	/* TODO Grantor ID comes from LPM lookup. */
	fe->u.request.grantor_id = 0;
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
gk_process_request(struct flow_entry *fe, struct ipacket *packet)
{
	int ret;
	uint64_t now = rte_rdtsc();
	uint8_t priority = priority_from_delta_time(now,
			fe->u.request.last_packet_seen_at);

	/* TODO The tunnel information should come from the LPM table. */
	struct ipip_tunnel_info tunnel;
	memset(&tunnel, 0, sizeof(tunnel));

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
	if (unlikely(priority > PRIORITY_MAX))
		priority = PRIORITY_MAX;

	/* The assigned priority is @priority. */

	/* Encapsulate the packet as a request. */
	ret = encapsulate(packet->pkt, priority, &tunnel);
	if (ret < 0)
		return ret;

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
	int ret;
	bool renew_cap;
	uint8_t priority = PRIORITY_GRANTED;
	uint64_t now = rte_rdtsc();
	struct rte_mbuf *pkt = packet->pkt;

	/* TODO The tunnel information should come from the LPM table. */
	struct ipip_tunnel_info tunnel;
	memset(&tunnel, 0, sizeof(tunnel));

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
	if (renew_cap) {
		fe->u.granted.send_next_renewal_at = now +
			fe->u.granted.renewal_step_cycle;
		priority = PRIORITY_RENEW_CAP;
	}

	/*
	 * Encapsulate packet as a granted packet,
	 * mark it as a capability renewal request if @renew_cap is true,
	 * enter destination according to @fe->u.granted.grantor_id.
	 */
	ret = encapsulate(packet->pkt, priority, &tunnel);
	if (ret < 0)
		return ret;

	/* TODO Put the encapsulated packet in the granted queue. */

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
	unsigned int socket_id = rte_lcore_to_socket_id(lcore_id);

	struct gk_instance *instance = &gk_conf->instances[block_idx];
	struct rte_hash_parameters ip_flow_hash_params = {
		.entries = gk_conf->flow_ht_size,
		.key_len = sizeof(struct ip_flow),
		.hash_func = rss_ip_flow_hf,
		.hash_func_init_val = 0,
	};

	ret = snprintf(ht_name, sizeof(ht_name), "ip_flow_hash_%u", block_idx);
	RTE_ASSERT(ret < sizeof(ht_name));

	/* Setup the flow hash table for GK block @block_idx. */
	ip_flow_hash_params.name = ht_name;
	ip_flow_hash_params.socket_id = socket_id;
	instance->ip_flow_hash_table = rte_hash_create(&ip_flow_hash_params);
	if (instance->ip_flow_hash_table == NULL) {
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
	if (instance->ip_flow_entry_table == NULL) {
		RTE_LOG(ERR, MALLOC,
			"The GK block can't create flow entry table at lcore %u!\n",
			lcore_id);

		ret = -1;
		goto flow_hash;
	}

	ret = init_mailbox("gk", MAILBOX_MAX_ENTRIES,
		sizeof(struct gk_cmd_entry), lcore_id, &instance->mb);
    	if (ret < 0)
        	goto flow_entry;

	ret = 0;
	goto out;

flow_entry:
    	rte_free(instance->ip_flow_entry_table);
    	instance->ip_flow_entry_table = NULL;
flow_hash:
	rte_hash_free(instance->ip_flow_hash_table);
	instance->ip_flow_hash_table = NULL;
out:
	return ret;
}

static void
add_ggu_policy(struct ggu_policy *policy, struct gk_instance *instance)
{
	int ret;
	uint64_t now = rte_rdtsc();
	struct flow_entry *fe;
	uint32_t rss_hash_val = rss_ip_flow_hf(&policy->flow, 0, 0);

	ret = rte_hash_lookup_with_hash(instance->ip_flow_hash_table,
		&policy->flow, rss_hash_val);
	if (ret < 0) {
		/* Create a new flow entry. */
		ret = rte_hash_add_key_with_hash(
			instance->ip_flow_hash_table,
 			(void *)&policy->flow, rss_hash_val);
		if (ret < 0) {
			RTE_LOG(ERR, HASH,
				"The GK block failed to add new key to hash table!\n");
			return;
		}

		fe = &instance->ip_flow_entry_table[ret];
		initialize_flow_entry(fe, &policy->flow);
	} else
		fe = &instance->ip_flow_entry_table[ret];

	switch(policy->state) {
	case GK_GRANTED:
		fe->state = GK_GRANTED;
		fe->u.granted.cap_expire_at = now +
			policy->params.u.granted.cap_expire_sec *
			cycles_per_sec;
		fe->u.granted.tx_rate_kb_cycle =
			policy->params.u.granted.tx_rate_kb_sec;
		fe->u.granted.send_next_renewal_at = now +
			policy->params.u.granted.next_renewal_ms *
			cycles_per_ms;
		fe->u.granted.renewal_step_cycle =
			policy->params.u.granted.renewal_step_ms *
			cycles_per_ms;
		fe->u.granted.budget_renew_at =
			now + cycle_from_second(1);
		fe->u.granted.budget_byte =
			fe->u.granted.tx_rate_kb_cycle * 1024;

		/* TODO Fill up the grantor id field. */
		break;

	case GK_DECLINED:
		fe->state = GK_DECLINED;
		fe->u.declined.expire_at = now +
			policy->params.u.declined.expire_sec * cycles_per_sec;
		break;

	default:
		RTE_LOG(ERR, GATEKEEPER,
			"gk: unknown flow state %u!\n", policy->state);
		break;
	}
}

static void
process_gk_cmd(struct gk_cmd_entry *entry, struct gk_instance *instance)
{
	switch(entry->op) {
	case GGU_POLICY_ADD:
		add_ggu_policy(&entry->u.ggu, instance);
		break;

	default:
		RTE_LOG(ERR, GATEKEEPER,
			"gk: unknown command operation %u\n", entry->op);
		break;
	}
}

static int
gk_setup_rss(struct gk_config *gk_conf)
{
	int ret = 0;
	unsigned int i;
	uint8_t port_in = gk_conf->net->front.id;
	uint16_t gk_queues[GK_MAX_NUM_LCORES];
	unsigned int num_lcores =
			gk_conf->lcore_end_id - gk_conf->lcore_start_id + 1;

	for (i = 0; i < num_lcores; i++)
		gk_queues[i] = gk_conf->instances[i].rx_queue_front;

	ret = gatekeeper_setup_rss(port_in, gk_queues, num_lcores);
	if (ret < 0)
		return ret;

	ret = gatekeeper_get_rss_config(port_in, &gk_conf->rss_conf);

	return ret;
}

static int
gk_proc(void *arg)
{
	/* TODO Implement the basic algorithm of a GK block. */

	int ret;
	unsigned int lcore = rte_lcore_id();
	struct gk_config *gk_conf = (struct gk_config *)arg;
	unsigned int block_idx = lcore - gk_conf->lcore_start_id;
	struct gk_instance *instance = &gk_conf->instances[block_idx];

	uint8_t port_in = get_net_conf()->front.id;
	uint8_t port_out = get_net_conf()->back.id;
	uint16_t rx_queue = instance->rx_queue_front;
	uint16_t tx_queue = instance->tx_queue_back;

	RTE_LOG(NOTICE, GATEKEEPER,
		"gk: the GK block is running at lcore = %u\n", lcore);

	gk_conf_hold(gk_conf);

	/* Wait for network devices to start. */
	while (gk_conf->net->configuring)
		;

	/*
	 * The RSS should be configured
	 * after the network devices are started.
	 */
	if (block_idx == 0) {
		ret = gk_setup_rss(gk_conf);
		if (ret < 0)
			exiting = true;
	}

	while (likely(!exiting)) {
		/* Get burst of RX packets, from first port of pair. */
		int i;
		int num_cmd;
		uint16_t num_rx;
		uint16_t num_tx = 0;
		uint16_t num_tx_succ;
		struct rte_mbuf *rx_bufs[GATEKEEPER_MAX_PKT_BURST];
		struct rte_mbuf *tx_bufs[GATEKEEPER_MAX_PKT_BURST];
		struct gk_cmd_entry *gk_cmds[GK_CMD_BURST_SIZE];

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

			ret = extract_packet_info(pkt, &packet);
			if (ret < 0) {
				/* Drop non-IP packets. */
				drop_packet(pkt);
				continue;
			}

			/* 
			 * Find the flow entry for the IP pair.
			 * Create a new flow entry if not found.
			 */
			ret = rte_hash_lookup_with_hash(
				instance->ip_flow_hash_table,
				&packet.flow, pkt->hash.rss);
			if (ret < 0) {
				/* Create a new flow entry. */
				ret = rte_hash_add_key_with_hash(
					instance->ip_flow_hash_table,
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
		num_tx_succ = rte_eth_tx_burst(port_out, tx_queue,
			tx_bufs, num_tx);

		/* XXX Do something better here! For now, free any unsent packets. */
		if (unlikely(num_tx_succ < num_tx)) {
			for (i = num_tx_succ; i < num_tx; i++)
				rte_pktmbuf_free(tx_bufs[i]);
		}

		/* Load a set of commands from its mailbox ring. */
        	num_cmd = mb_dequeue_burst(&instance->mb,
                	(void **)gk_cmds, GK_CMD_BURST_SIZE);

        	for (i = 0; i < num_cmd; i++) {
			process_gk_cmd(gk_cmds[i], instance);
			mb_free_entry(&instance->mb, gk_cmds[i]);
        	}
	}

	RTE_LOG(NOTICE, GATEKEEPER,
		"gk: the GK block at lcore = %u is exiting\n", lcore);

	return gk_conf_put(gk_conf);
}

struct gk_config *
alloc_gk_conf(void)
{
	return rte_calloc("gk_config", 1, sizeof(struct gk_config), 0);
}

static int
cleanup_gk(struct gk_config *gk_conf)
{
	unsigned int i;
	unsigned int num_lcores = gk_conf->lcore_end_id -
		gk_conf->lcore_start_id + 1;

	for (i = 0; i < num_lcores; i++) {
		if (gk_conf->instances[i].ip_flow_hash_table)
			rte_hash_free(gk_conf->instances[i].
				ip_flow_hash_table);

		if (gk_conf->instances[i].ip_flow_entry_table)
			rte_free(gk_conf->instances[i].
				ip_flow_entry_table);

                destroy_mailbox(&gk_conf->instances[i].mb);
	}

	rte_free(gk_conf->instances);
	rte_free(gk_conf);

	return 0;
}

int
gk_conf_put(struct gk_config *gk_conf)
{
	/*
	 * Atomically decrements the atomic counter (v) by one and returns true 
	 * if the result is 0, or false in all other cases.
	 */
	if (rte_atomic32_dec_and_test(&gk_conf->ref_cnt))
		return cleanup_gk(gk_conf);

	return 0;
}

int
run_gk(struct net_config *net_conf, struct gk_config *gk_conf)
{
	/* TODO Initialize and run GK functional block. */

	unsigned int i;
	unsigned int num_lcores;
	int ret = 0;
	struct gk_instance *inst_ptr;

	if (net_conf == NULL || gk_conf == NULL) {
		ret = -1;
		goto out;
	}

	if (!net_conf->back_iface_enabled) {
		RTE_LOG(ERR, GATEKEEPER, "gk: back interface is required\n");
		ret = -1;
		goto out;
	}

	gk_conf->net = net_conf;

	num_lcores = gk_conf->lcore_end_id - gk_conf->lcore_start_id + 1;
	RTE_ASSERT(num_lcores <= GK_MAX_NUM_LCORES);

	gk_conf->instances = (struct gk_instance *)rte_calloc(NULL,
		num_lcores, sizeof(struct gk_instance), 0);
	if (gk_conf->instances == NULL) {
		ret = -1;
		goto out;
	}

	/* Set up queue identifiers now for RSS, before instances start. */
	for (i = 0; i < num_lcores; i++) {
		unsigned int lcore = i + gk_conf->lcore_start_id;
		inst_ptr = &gk_conf->instances[i];

		ret = get_queue_id(&gk_conf->net->front, QUEUE_TYPE_RX, lcore);
		if (ret < 0) {
			RTE_LOG(ERR, GATEKEEPER, "gk: cannot assign an RX queue for the front interface for lcore %u\n",
				lcore);
			goto out;
		}
		inst_ptr->rx_queue_front = (uint16_t)ret;

		ret = get_queue_id(&gk_conf->net->back, QUEUE_TYPE_TX, lcore);
		if (ret < 0) {
			RTE_LOG(ERR, GATEKEEPER, "gk: cannot assign a TX queue for the back interface for lcore %u\n",
				lcore);
			goto out;
		}
		inst_ptr->tx_queue_back = (uint16_t)ret;
	}

	rte_atomic32_init(&gk_conf->ref_cnt);

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

	ret = 0;
	goto out;

instance:
	/* GK instance at lcore @i failed to launch. */
	inst_ptr = &gk_conf->instances[i - gk_conf->lcore_start_id];
	
	rte_hash_free(inst_ptr->ip_flow_hash_table);
	inst_ptr->ip_flow_hash_table = NULL;

	rte_free(inst_ptr->ip_flow_entry_table);
	inst_ptr->ip_flow_entry_table = NULL;

	destroy_mailbox(&inst_ptr->mb);

setup:
	/*
	 * If failed to setup the first gk instance, needs to release
	 * 'gk_conf->instances' and 'gk_conf'.
	 * Otherwise, the launched gk instances need to call
	 * gk_conf_put() to release.
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

struct mailbox *
get_responsible_gk_mailbox(const struct ip_flow *flow,
	const struct gk_config *gk_conf)
{
	/*
	 * Calculate the RSS hash value for the
	 * pair <Src, Dst> in the decision.
	 */
	uint32_t rss_hash_val = rss_ip_flow_hf(flow, 0, 0);
	uint32_t i;
	uint32_t idx;
	uint32_t shift;
	uint16_t queue_id;
	int block_id = -1;

	/*
	 * XXX Change the mapping rss hash value to rss reta entry
	 * if the reta size is not 128.
	 */
	RTE_ASSERT(gk_conf->rss_conf.reta_size == 128);
	rss_hash_val = (rss_hash_val & 127);

	/*
	 * Identify which GK block is responsible for the
	 * pair <Src, Dst> in the decision.
	 */
	idx = rss_hash_val / RTE_RETA_GROUP_SIZE;
	shift = rss_hash_val % RTE_RETA_GROUP_SIZE;
	queue_id = gk_conf->rss_conf.reta_conf[idx].reta[shift];

	/* XXX Change mapping queue id to the gk instance id efficiently. */
	for (i = gk_conf->lcore_start_id; i<= gk_conf->lcore_end_id; i++) {
		if (gk_conf->instances[i - gk_conf->lcore_start_id].
				rx_queue_front == queue_id)
			block_id = i - gk_conf->lcore_start_id;
	}

	if (block_id == -1)
		RTE_LOG(ERR, GATEKEEPER,
			"gk: wrong RSS configuration for GK blocks!\n");

	RTE_ASSERT(gk_conf->lcore_start_id + block_id <= gk_conf->lcore_end_id);

	return &gk_conf->instances[block_id].mb;
}
