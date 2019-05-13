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
#include <math.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>

#include <rte_ip.h>
#include <rte_log.h>
#include <rte_hash.h>
#include <rte_lcore.h>
#include <rte_ethdev.h>
#include <rte_memcpy.h>
#include <rte_cycles.h>
#include <rte_malloc.h>
#include <rte_icmp.h>

#include "gatekeeper_acl.h"
#include "gatekeeper_gk.h"
#include "gatekeeper_main.h"
#include "gatekeeper_lls.h"
#include "gatekeeper_config.h"
#include "gatekeeper_launch.h"
#include "gatekeeper_l2.h"
#include "gatekeeper_sol.h"
#include "gatekeeper_lls.h"
#include "gatekeeper_flow_bpf.h"

#include "bpf.h"

#define	START_PRIORITY		 (38)
/* Set @START_ALLOWANCE as the double size of a large DNS reply. */
#define	START_ALLOWANCE		 (8)

int gk_logtype;

/* Store information about a packet. */
struct ipacket {
	/* Flow identifier for this packet. */
	struct ip_flow  flow;
	/* Pointer to the packet itself. */
	struct rte_mbuf *pkt;
	/* Pointer to the l3 header. */
	void *l3_hdr;
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
		GK_LOG(ERR, "The present time smaller than the past time\n");
		return 0;
	}

	delta_time = (present - past) * picosec_per_cycle;
	if (unlikely(delta_time < 1))
		return 0;
	
	return integer_log_base_2(delta_time);
}

static struct gk_fib *
look_up_fib(struct gk_lpm *ltbl, struct ip_flow *flow)
{
	int fib_id;

	if (flow->proto == RTE_ETHER_TYPE_IPV4) {
		fib_id = lpm_lookup_ipv4(ltbl->lpm, flow->f.v4.dst.s_addr);
		if (fib_id < 0)
			return NULL;
		return &ltbl->fib_tbl[fib_id];
	}

	if (likely(flow->proto == RTE_ETHER_TYPE_IPV6)) {
		fib_id = lpm_lookup_ipv6(ltbl->lpm6, &flow->f.v6.dst);
		if (fib_id < 0)
			return NULL;
		return &ltbl->fib_tbl6[fib_id];
	}

	rte_panic("Unexpected condition at %s: unknown flow type %hu\n",
		__func__, flow->proto);

	return NULL; /* Unreachable. */
}

static int
extract_packet_info(struct rte_mbuf *pkt, struct ipacket *packet)
{
	int ret = 0;
	uint16_t ether_type;
	struct rte_ether_hdr *eth_hdr;
	struct rte_ipv4_hdr *ip4_hdr;
	struct rte_ipv6_hdr *ip6_hdr;
	uint16_t pkt_len = rte_pktmbuf_data_len(pkt);

	eth_hdr = rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);
	ether_type = rte_be_to_cpu_16(pkt_in_skip_l2(pkt, eth_hdr,
		&packet->l3_hdr));

	switch (ether_type) {
	case RTE_ETHER_TYPE_IPV4:
		if (pkt_len < sizeof(*eth_hdr) + sizeof(*ip4_hdr)) {
			packet->flow.proto = 0;
			GK_LOG(NOTICE,
				"Packet is too short to be IPv4 (%" PRIu16 ")\n",
				pkt_len);
			ret = -1;
			goto out;
		}

		ip4_hdr = packet->l3_hdr;
		packet->flow.proto = RTE_ETHER_TYPE_IPV4;
		packet->flow.f.v4.src.s_addr = ip4_hdr->src_addr;
		packet->flow.f.v4.dst.s_addr = ip4_hdr->dst_addr;
		break;

	case RTE_ETHER_TYPE_IPV6:
		if (pkt_len < sizeof(*eth_hdr) + sizeof(*ip6_hdr)) {
			packet->flow.proto = 0;
			GK_LOG(NOTICE,
				"Packet is too short to be IPv6 (%" PRIu16 ")\n",
				pkt_len);
			ret = -1;
			goto out;
		}

		ip6_hdr = packet->l3_hdr;
		packet->flow.proto = RTE_ETHER_TYPE_IPV6;
		rte_memcpy(packet->flow.f.v6.src.s6_addr, ip6_hdr->src_addr,
			sizeof(packet->flow.f.v6.src.s6_addr));
		rte_memcpy(packet->flow.f.v6.dst.s6_addr, ip6_hdr->dst_addr,
			sizeof(packet->flow.f.v6.dst.s6_addr));
		break;

	case RTE_ETHER_TYPE_ARP:
		packet->flow.proto = RTE_ETHER_TYPE_ARP;
		ret = -1;
		break;

	default:
		packet->flow.proto = 0;
		log_unknown_l2("gk", ether_type);
		ret = -1;
		break;
	}
out:
	packet->pkt = pkt;
	return ret;
}

static inline void
initialize_flow_entry(struct flow_entry *fe,
	struct ip_flow *flow, struct gk_fib *grantor_fib)
{
	/*
	 * The flow table is a critical data structure, so,
	 * whenever the size of entries grow too much,
	 * one must look for alternatives before increasing
	 * the limit below.
	 */
	RTE_BUILD_BUG_ON(sizeof(*fe) > 128);

	rte_memcpy(&fe->flow, flow, sizeof(*flow));

	fe->state = GK_REQUEST;
	fe->u.request.last_packet_seen_at = rte_rdtsc();
	fe->u.request.last_priority = START_PRIORITY;
	fe->u.request.allowance = START_ALLOWANCE - 1;
	fe->grantor_fib = grantor_fib;
}

static inline void
reinitialize_flow_entry(struct flow_entry *fe, uint64_t now)
{
	fe->state = GK_REQUEST;
	fe->u.request.last_packet_seen_at = now;
	fe->u.request.last_priority = START_PRIORITY;
	fe->u.request.allowance = START_ALLOWANCE - 1;
}

typedef int (*packet_drop_cb_func)(struct rte_mbuf *pkt,
	struct gk_instance *instance);

static int
drop_packet_front(struct rte_mbuf *pkt, struct gk_instance *instance)
{
	instance->traffic_stats.tot_pkts_num_dropped++;
	instance->traffic_stats.tot_pkts_size_dropped +=
		rte_pktmbuf_pkt_len(pkt);

	return drop_packet(pkt);
}

static inline int
drop_packet_back(struct rte_mbuf *pkt,
	__attribute__((unused)) struct gk_instance *instance)
{
	return drop_packet(pkt);
}

/*
 * Return value indicates whether the cached Ethernet header is stale or not.
 */
int
pkt_copy_cached_eth_header(struct rte_mbuf *pkt, struct ether_cache *eth_cache,
	size_t l2_hdr_len)
{
	unsigned seq;
	bool stale;

	do {
		seq = read_seqbegin(&eth_cache->lock);
		stale = eth_cache->stale;
		if (!stale) {
			struct ether_hdr *eth_hdr =
				rte_pktmbuf_mtod(pkt, struct ether_hdr *);
			rte_memcpy(eth_hdr,
				&eth_cache->l2_hdr, l2_hdr_len);
			pkt->l2_len = l2_hdr_len;
		}
	} while (read_seqretry(&eth_cache->lock, seq));

	return stale;
}

/* 
 * When a flow entry is at request state, all the GK block processing
 * that entry does is to:
 * (1) compute the priority of the packet.
 * (2) encapsulate the packet as a request.
 * (3) put this encapsulated packet in the request queue.
 *
 * Returns a negative integer on error, or EINPROGRESS to indicate
 * that the request is being processed by another lcore, and should
 * not be forwarded or dropped on returning from this function.
 */
static int
gk_process_request(struct flow_entry *fe, struct ipacket *packet,
	struct sol_config *sol_conf, struct gk_measurement_metrics *stats)
{
	int ret;
	uint64_t now = rte_rdtsc();
	uint8_t priority = priority_from_delta_time(now,
			fe->u.request.last_packet_seen_at);
	struct gk_fib *fib = fe->grantor_fib;
	struct ether_cache *eth_cache;

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
	ret = encapsulate(packet->pkt, priority,
		&sol_conf->net->back, &fib->u.grantor.gt_addr);
	if (ret < 0)
		return ret;

	eth_cache = fib->u.grantor.eth_cache;
	RTE_VERIFY(eth_cache != NULL);
	/* If needed, packet header space was adjusted by encapsulate(). */
	if (pkt_copy_cached_eth_header(packet->pkt, eth_cache,
			sol_conf->net->back.l2_len_out))
		return -1;

	ret = gk_solicitor_enqueue(sol_conf, packet->pkt, priority);
	if (ret < 0)
		return ret;

	stats->pkts_num_request++;
	stats->pkts_size_request += rte_pktmbuf_pkt_len(packet->pkt);

	return EINPROGRESS;
}

/*
 * Returns:
 *   * zero on success; the granted packet can be enqueued and forwarded
 *   * a negative number on error or when the packet needs to be
 *     otherwise dropped because it has exceeded its budget
 *   * EINPROGRESS to indicate that the packet is now a request that
 *     is being processed by another lcore, and should not
 *     be forwarded or dropped on returning from this function.
 */
static int
gk_process_granted(struct flow_entry *fe, struct ipacket *packet,
	struct sol_config *sol_conf, struct gk_measurement_metrics *stats)
{
	int ret;
	bool renew_cap;
	uint8_t priority = PRIORITY_GRANTED;
	uint64_t now = rte_rdtsc();
	struct rte_mbuf *pkt = packet->pkt;
	struct gk_fib *fib = fe->grantor_fib;
	struct ether_cache *eth_cache;
	uint32_t pkt_len;

	if (now >= fe->u.granted.cap_expire_at) {
		reinitialize_flow_entry(fe, now);
		return gk_process_request(fe, packet, sol_conf, stats);
	}

	if (now >= fe->u.granted.budget_renew_at) {
		fe->u.granted.budget_renew_at = now + cycles_per_sec;
		fe->u.granted.budget_byte =
			(uint64_t)fe->u.granted.tx_rate_kb_cycle * 1024;
	}

	pkt_len = rte_pktmbuf_pkt_len(pkt);
	if (pkt_len > fe->u.granted.budget_byte) {
		stats->pkts_num_declined++;
		stats->pkts_size_declined += pkt_len;
		return -1;
	}

	fe->u.granted.budget_byte -= pkt_len;
	renew_cap = now >= fe->u.granted.send_next_renewal_at;
	if (renew_cap) {
		fe->u.granted.send_next_renewal_at = now +
			fe->u.granted.renewal_step_cycle;
		priority = PRIORITY_RENEW_CAP;
	}

	/*
	 * Encapsulate packet as a granted packet,
	 * mark it as a capability renewal request if @renew_cap is true,
	 * enter destination according to @fe->grantor_fib.
	 */
	ret = encapsulate(packet->pkt, priority,
		&sol_conf->net->back, &fib->u.grantor.gt_addr);
	if (ret < 0)
		return ret;

	eth_cache = fib->u.grantor.eth_cache;
	RTE_VERIFY(eth_cache != NULL);
	/* If needed, packet header space was adjusted by encapsulate(). */
	if (pkt_copy_cached_eth_header(packet->pkt, eth_cache,
			sol_conf->net->back.l2_len_out))
		return -1;

	stats->pkts_num_granted++;
	stats->pkts_size_granted += pkt_len;
	return 0;
}

/*
 * Returns:
 *   * a negative number on error or when the packet needs to be
 *     otherwise dropped because it is declined
 *   * EINPROGRESS to indicate that the packet is now a request that
 *     is being processed by another lcore, and should not
 *     be forwarded or dropped on returning from this function.
 */
static int
gk_process_declined(struct flow_entry *fe, struct ipacket *packet,
	struct sol_config *sol_conf, struct gk_measurement_metrics *stats)
{
	uint64_t now = rte_rdtsc();

	if (unlikely(now >= fe->u.declined.expire_at)) {
		reinitialize_flow_entry(fe, now);
		return gk_process_request(fe, packet, sol_conf, stats);
	}

	stats->pkts_num_declined++;
	stats->pkts_size_declined += rte_pktmbuf_pkt_len(packet->pkt);

	return -1;
}

/*
 * Returns:
 *   * zero on success; the packet can be enqueued and forwarded
 *   * a negative number on error or when the packet needs to be
 *     otherwise dropped because it has exceeded a limit
 *   * EINPROGRESS to indicate that the packet is now a request that
 *     is being processed by another lcore, and should not
 *     be forwarded or dropped on returning from this function.
 */
static int
gk_process_bpf(struct flow_entry *fe, struct ipacket *packet,
	struct gk_config *gk_conf, struct gk_measurement_metrics *stats)
{
	struct gk_bpf_pkt_ctx ctx;
	uint64_t bpf_ret;
	int program_index, rc;

	ctx.now = rte_rdtsc();
	ctx.expire_at = fe->u.bpf.expire_at;
	if (unlikely(ctx.now >= ctx.expire_at))
		goto expired;

	program_index = fe->u.bpf.program_index;
	rc = gk_bpf_decide_pkt(gk_conf, program_index, fe, packet->pkt, &ctx,
		&bpf_ret);
	if (unlikely(rc != 0)) {
		GK_LOG(WARNING,
			"The BPF program at index %u failed to run its function pkt\n",
			program_index);
		goto expired;
	}

	switch (bpf_ret) {
	case GK_BPF_PKT_RET_FORWARD: {
		struct ether_cache *eth_cache =
			fe->grantor_fib->u.grantor.eth_cache;
		RTE_VERIFY(eth_cache != NULL);
		/*
		 * If needed, encapsulate() already adjusted
		 * packet header space.
		 */
		if (pkt_copy_cached_eth_header(packet->pkt, eth_cache,
				gk_conf->net->back.l2_len_out))
			return -1;

		stats->pkts_num_granted++;
		stats->pkts_size_granted += rte_pktmbuf_pkt_len(packet->pkt);
		return 0;
	}
	case GK_BPF_PKT_RET_DECLINE:
		stats->pkts_num_declined++;
		stats->pkts_size_declined += rte_pktmbuf_pkt_len(packet->pkt);
		return -1;
	case GK_BPF_PKT_RET_ERROR:
		GK_LOG(WARNING,
			"The function pkt of the BPF program at index %u returned GK_BPF_PKT_RET_ERROR\n",
			program_index);
		return -1;
	default:
		GK_LOG(WARNING,
			"The function pkt of the BPF program at index %u returned an invalid return: %" PRIu64 "\n",
			program_index, bpf_ret);
		return -1;
	}

	rte_panic("Unexpected condition at %s()", __func__);

expired:
	reinitialize_flow_entry(fe, ctx.now);
	return gk_process_request(fe, packet, gk_conf->sol_conf, stats);
}

static int
get_block_idx(struct gk_config *gk_conf, unsigned int lcore_id)
{
	int i;
	for (i = 0; i < gk_conf->num_lcores; i++)
		if (gk_conf->lcores[i] == lcore_id)
			return i;
	rte_panic("Unexpected condition: lcore %u is not running a gk block\n",
		lcore_id);
	return 0;
}

static bool
is_flow_expired(struct flow_entry *fe,
	uint64_t now, uint64_t request_timeout_cycles)
{
	switch(fe->state) {
	case GK_REQUEST:
		if (fe->u.request.last_packet_seen_at > now) {
			char err_msg[128];
			int ret = snprintf(err_msg, sizeof(err_msg),
				"gk: buggy condition at %s: wrong timestamp",
				__func__);
			RTE_VERIFY(ret > 0 && ret < (int)sizeof(err_msg));
			print_flow_err_msg(&fe->flow, err_msg);
			return true;
		}

		return now - fe->u.request.last_packet_seen_at >=
			request_timeout_cycles;
	case GK_GRANTED:
		return now >= fe->u.granted.cap_expire_at;
	case GK_DECLINED:
		return now >= fe->u.declined.expire_at;
	case GK_BPF:
		return now >= fe->u.bpf.expire_at;
	default:
		return true;
	}
}

static int
gk_del_flow_entry_from_hash(struct rte_hash *h, struct flow_entry *fe)
{
	int ret = rte_hash_del_key(h, &fe->flow);
	if (likely(ret >= 0))
		memset(fe, 0, sizeof(*fe));
	else {
		GK_LOG(ERR,
			"The GK block failed to delete a key from hash table at %s: %s\n",
			__func__, strerror(-ret));
	}

	return ret;
}

static void
gk_flow_tbl_bucket_scan(uint32_t *bidx,
	uint64_t request_timeout_cycles, struct gk_instance *instance)
{
	int32_t index;
	const struct ip_flow *key;
	void *data;
	uint32_t next = 0;
	uint64_t now = rte_rdtsc();

	index = rte_hash_bucket_iterate(instance->ip_flow_hash_table,
		(void *)&key, &data, bidx, &next);
	while (index >= 0) {
		struct flow_entry *fe = &instance->ip_flow_entry_table[index];
		if (is_flow_expired(fe, now, request_timeout_cycles)) {
			gk_del_flow_entry_from_hash(
				instance->ip_flow_hash_table, fe);
		}

		index = rte_hash_bucket_iterate(instance->ip_flow_hash_table,
			(void *)&key, &data, bidx, &next);
	}
}

static int
setup_gk_instance(unsigned int lcore_id, struct gk_config *gk_conf)
{
	int  ret;
	char ht_name[64];
	unsigned int block_idx = get_block_idx(gk_conf, lcore_id);
	unsigned int socket_id = rte_lcore_to_socket_id(lcore_id);
	unsigned int gk_max_pkt_burst = RTE_MAX(gk_conf->front_max_pkt_burst,
		gk_conf->back_max_pkt_burst);

	struct gk_instance *instance = &gk_conf->instances[block_idx];
	struct rte_hash_parameters ip_flow_hash_params = {
		.entries = gk_conf->flow_ht_size,
		.key_len = sizeof(struct ip_flow),
		.hash_func = rss_ip_flow_hf,
		.hash_func_init_val = 0,
	};

	ret = snprintf(ht_name, sizeof(ht_name), "ip_flow_hash_%u", block_idx);
	RTE_VERIFY(ret > 0 && ret < (int)sizeof(ht_name));

	/* Setup the flow hash table for GK block @block_idx. */
	ip_flow_hash_params.name = ht_name;
	ip_flow_hash_params.socket_id = socket_id;
	instance->ip_flow_hash_table = rte_hash_create(&ip_flow_hash_params);
	if (instance->ip_flow_hash_table == NULL) {
		GK_LOG(ERR,
			"The GK block cannot create hash table at lcore %u\n",
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
		GK_LOG(ERR,
			"The GK block can't create flow entry table at lcore %u\n",
			lcore_id);

		ret = -1;
		goto flow_hash;
	}

	instance->acl4 = alloc_acl_search(gk_max_pkt_burst);
	if (instance->acl4 == NULL) {
		GK_LOG(ERR,
			"The GK block can't create acl search for IPv4 at lcore %u\n",
			lcore_id);

		ret = -1;
		goto flow_entry;
	}

	instance->acl6 = alloc_acl_search(gk_max_pkt_burst);
	if (instance->acl6 == NULL) {
		GK_LOG(ERR,
			"The GK block can't create acl search for IPv6 at lcore %u\n",
			lcore_id);

		ret = -1;
		goto acl4_search;
	}

	ret = init_mailbox("gk", gk_conf->mailbox_max_entries_exp,
		sizeof(struct gk_cmd_entry), gk_conf->mailbox_mem_cache_size,
		lcore_id, &instance->mb);
    	if (ret < 0)
		goto acl6_search;

	tb_ratelimit_state_init(&instance->front_icmp_rs,
		gk_conf->front_icmp_msgs_per_sec,
		gk_conf->front_icmp_msgs_burst);
	tb_ratelimit_state_init(&instance->back_icmp_rs,
		gk_conf->back_icmp_msgs_per_sec,
		gk_conf->back_icmp_msgs_burst);

	ret = 0;
	goto out;

acl6_search:
	destroy_acl_search(instance->acl6);
	instance->acl6 = NULL;
acl4_search:
	destroy_acl_search(instance->acl4);
	instance->acl4 = NULL;
flow_entry:
    	rte_free(instance->ip_flow_entry_table);
    	instance->ip_flow_entry_table = NULL;
flow_hash:
	rte_hash_free(instance->ip_flow_hash_table);
	instance->ip_flow_hash_table = NULL;
out:
	return ret;
}

static struct flow_entry *
find_flow_entry_candidate(struct gk_instance *instance,
	uint32_t bidx, uint64_t request_timeout_cycles,
	enum gk_flow_state state_to_add)
{
	int32_t index;
	uint32_t next = 0;
	const struct ip_flow *key;
	struct flow_entry *last_fe = NULL;
	void *data;
	uint64_t now = rte_rdtsc();

	index = rte_hash_bucket_iterate(instance->ip_flow_hash_table,
		(void *)&key, &data, &bidx, &next);
	while (index >= 0) {
		struct flow_entry *fe = &instance->ip_flow_entry_table[index];

		/* Expired flow entry. */
		if (is_flow_expired(fe, now, request_timeout_cycles))
			return fe;

		/*
		 * Only flow entries with state GK_REQUEST
		 * will be possibly repaced, others have a higher priority.
		 */
		if (fe->state == GK_REQUEST) {
			uint8_t priority = priority_from_delta_time(now,
				fe->u.request.last_packet_seen_at);
			/*
			 * Do not favor request entries that are not doubling
			 * its priority when a Gatekeeper server is overloaded.
			 * We use +2 instead of +1 in the test below to account
			 * for random delays in the network.
			 */
			if (priority > fe->u.request.last_priority + 2)
				return fe;

			if (state_to_add != GK_REQUEST && (last_fe == NULL ||
					last_fe->u.request.last_packet_seen_at >
					fe->u.request.last_packet_seen_at))
				last_fe = fe;
		}

		index = rte_hash_bucket_iterate(instance->ip_flow_hash_table,
			(void *)&key, &data, &bidx, &next);
	}

	return last_fe;
}

static int
drop_flow_entry_heuristically(struct gk_instance *instance,
	hash_sig_t sig, uint64_t request_timeout_cycles,
	enum gk_flow_state state_to_add)
{
	uint32_t primary_bidx = rte_hash_get_primary_bucket(
		instance->ip_flow_hash_table, sig);
	struct flow_entry *fe = find_flow_entry_candidate(
		instance, primary_bidx, request_timeout_cycles, state_to_add);
	if (fe == NULL)
		return -ENOSPC;

	return gk_del_flow_entry_from_hash(instance->ip_flow_hash_table, fe);
}

/*
 * We heuristically drop entries to alleviate memory pressure
 * when the table is full.
 */
static int
gk_hash_add_flow_entry(struct gk_instance *instance,
	struct ip_flow *flow, unsigned int request_timeout_cycles,
	uint32_t rss_hash_val, enum gk_flow_state state_to_add)
{
	while (true) {
		int ret = rte_hash_add_key_with_hash(
			instance->ip_flow_hash_table, flow, rss_hash_val);
		if (ret == -ENOSPC) {
			GK_LOG(WARNING,
				"The GK block failed to add new key to hash table in %s due to lack of space\n",
				__func__);
			ret = drop_flow_entry_heuristically(instance,
				rss_hash_val, request_timeout_cycles,
				state_to_add);
			if (ret < 0)
				return -ENOSPC;
			continue;
		}

		if (ret < 0) {
			GK_LOG(ERR,
				"The GK block failed to add a new key to hash table in %s: %s\n",
				__func__, strerror(-ret));
		}

		return ret;
	}
}

/*
 * This function is only called when a policy from GGU block
 * tries to add a new flow entry in the flow table.
 *
 * Notice, the function doesn't fully initialize the new flow entry,
 * instead it only initializes the @flow and @grantor_fib fields.
 */
static struct flow_entry *
add_new_flow_from_policy(
	struct ggu_policy *policy, struct gk_instance *instance,
	struct gk_config *gk_conf, uint32_t rss_hash_val)
{
	int ret;
	struct gk_fib *fib;
	struct flow_entry *fe;
	struct gk_lpm *ltbl = &gk_conf->lpm_tbl;

	fib = look_up_fib(ltbl, &policy->flow);
	if (fib == NULL || fib->action != GK_FWD_GRANTOR) {
		/*
		 * Drop this solicitation to add
		 * a policy decision.
		 */
		char err_msg[128];
		ret = snprintf(err_msg, sizeof(err_msg),
			"gk: at %s initialize flow entry error", __func__);
		RTE_VERIFY(ret > 0 && ret < (int)sizeof(err_msg));
		print_flow_err_msg(&policy->flow, err_msg);
		return NULL;
	}

	ret = gk_hash_add_flow_entry(instance, &policy->flow,
		gk_conf->request_timeout_cycles, rss_hash_val, policy->state);
	if (ret < 0)
		return NULL;

	fe = &instance->ip_flow_entry_table[ret];
	rte_memcpy(&fe->flow, &policy->flow, sizeof(fe->flow));

	fe->grantor_fib = fib;

	return fe;
}

static void
add_ggu_policy(struct ggu_policy *policy,
	struct gk_instance *instance, struct gk_config *gk_conf)
{
	int ret;
	uint64_t now = rte_rdtsc();
	struct flow_entry *fe;
	uint32_t rss_hash_val = rss_ip_flow_hf(&policy->flow, 0, 0);

	/*
	 * When the flow entry already exists,
	 * the grantor ID should be already known.
	 * Otherwise, Grantor ID comes from LPM lookup.
	 */
	ret = rte_hash_lookup_with_hash(instance->ip_flow_hash_table,
		&policy->flow, rss_hash_val);
	if (ret < 0) {
		/*
	 	 * The function add_ggu_policy() only fills up
		 * GK_GRANTED and GK_DECLINED states. So, it doesn't
		 * need to call initialize_flow_entry().
		 */
		fe = add_new_flow_from_policy(
			policy, instance, gk_conf, rss_hash_val);
		if (fe == NULL)
			return;
	} else
		fe = &instance->ip_flow_entry_table[ret];

	switch (policy->state) {
	case GK_GRANTED:
		fe->state = GK_GRANTED;
		fe->u.granted.cap_expire_at = now +
			policy->params.granted.cap_expire_sec *
			cycles_per_sec;
		fe->u.granted.tx_rate_kb_cycle =
			policy->params.granted.tx_rate_kb_sec;
		fe->u.granted.send_next_renewal_at = now +
			policy->params.granted.next_renewal_ms *
			cycles_per_ms;
		fe->u.granted.renewal_step_cycle =
			policy->params.granted.renewal_step_ms *
			cycles_per_ms;
		fe->u.granted.budget_renew_at = now + cycles_per_sec;
		fe->u.granted.budget_byte =
			(uint64_t)fe->u.granted.tx_rate_kb_cycle * 1024;
		break;

	case GK_DECLINED:
		fe->state = GK_DECLINED;
		fe->u.declined.expire_at = now +
			policy->params.declined.expire_sec * cycles_per_sec;
		break;

	case GK_BPF:
		fe->state = GK_BPF;
		fe->u.bpf.expire_at = now +
			policy->params.bpf.expire_sec * cycles_per_sec;
		fe->u.bpf.program_index = policy->params.bpf.program_index;
		fe->u.bpf.cookie = policy->params.bpf.cookie;
		break;

	default:
		GK_LOG(ERR, "Unknown flow state %u\n", policy->state);
		break;
	}
}

static void
flush_flow_table(struct ip_prefix *src,
	struct ip_prefix *dst, struct gk_instance *instance)
{
	uint16_t proto;
	uint32_t next = 0;
	int32_t index;
	uint64_t num_flushed_flows = 0;
	const struct ip_flow *key;
	void *data;
	struct in_addr ip4_src_mask;
	struct in_addr ip4_dst_mask;
	struct in6_addr ip6_src_mask;
	struct in6_addr ip6_dst_mask;

	RTE_VERIFY(src->addr.proto == dst->addr.proto);

	if (src->addr.proto == RTE_ETHER_TYPE_IPV4) {
		ip4_prefix_mask(src->len, &ip4_src_mask);
		ip4_prefix_mask(dst->len, &ip4_dst_mask);

		memset(&ip6_src_mask, 0, sizeof(ip6_src_mask));
		memset(&ip6_dst_mask, 0, sizeof(ip6_dst_mask));

		proto = RTE_ETHER_TYPE_IPV4;
	} else if (likely(src->addr.proto == RTE_ETHER_TYPE_IPV6)) {
		memset(&ip4_src_mask, 0, sizeof(ip4_src_mask));
		memset(&ip4_dst_mask, 0, sizeof(ip4_dst_mask));

		ip6_prefix_mask(src->len, &ip6_src_mask);
		ip6_prefix_mask(dst->len, &ip6_dst_mask);

		proto = RTE_ETHER_TYPE_IPV6;
	} else
		rte_panic("Unexpected protocol: %i\n", src->addr.proto);

	index = rte_hash_iterate(instance->ip_flow_hash_table,
		(void *)&key, &data, &next);
	while (index >= 0) {
		bool matched = true;
		struct flow_entry *fe =
			&instance->ip_flow_entry_table[index];

		if (proto != fe->flow.proto)
			goto next;

		if (proto == RTE_ETHER_TYPE_IPV4) {
			if (src->len != 0) {
				matched = ip4_same_subnet(
					src->addr.ip.v4.s_addr,
					fe->flow.f.v4.src.s_addr,
					ip4_src_mask.s_addr);
			}

			if (matched && dst->len != 0) {
				matched = ip4_same_subnet(
					dst->addr.ip.v4.s_addr,
					fe->flow.f.v4.dst.s_addr,
					ip4_dst_mask.s_addr);
			}
		} else {
			if (src->len != 0) {
				matched = ip6_same_subnet(
					&src->addr.ip.v6,
					&fe->flow.f.v6.src,
					&ip6_src_mask);
			}

			if (matched && dst->len != 0) {
				matched = ip6_same_subnet(
					&dst->addr.ip.v6,
					&fe->flow.f.v6.dst,
					&ip6_dst_mask);
			}
		}

		if (matched) {
			gk_del_flow_entry_from_hash(
				instance->ip_flow_hash_table, fe);
			num_flushed_flows++;
		}

next:
		index = rte_hash_iterate(instance->ip_flow_hash_table,
			(void *)&key, &data, &next);
	}

	GK_LOG(NOTICE,
		"The GK block finished flushing %" PRIu64
		" flows in the flow table at %s with lcore %u\n",
		num_flushed_flows, __func__, rte_lcore_id());
}

static void
gk_synchronize(struct gk_fib *fib, struct gk_instance *instance)
{
	switch (fib->action) {
	case GK_FWD_GRANTOR: {
		/* Flush the grantor @fib in the flow table. */

		uint32_t next = 0;
		int32_t index;
		const struct ip_flow *key;
		void *data;

		index = rte_hash_iterate(instance->ip_flow_hash_table,
			(void *)&key, &data, &next);
		while (index >= 0) {
			struct flow_entry *fe =
				&instance->ip_flow_entry_table[index];
			if (fe->grantor_fib == fib) {
				gk_del_flow_entry_from_hash(
					instance->ip_flow_hash_table, fe);
			}

			index = rte_hash_iterate(instance->ip_flow_hash_table,
				(void *)&key, &data, &next);
		}

		GK_LOG(NOTICE, "Finished flushing flow table at lcore %u\n",
			rte_lcore_id());

		break;
	}

	case GK_FWD_GATEWAY_FRONT_NET:
		/* FALLTHROUGH */
	case GK_FWD_GATEWAY_BACK_NET:
		/* FALLTHROUGH */
	case GK_DROP:
		/* FALLTHROUGH */
	case GK_FWD_NEIGHBOR_FRONT_NET:
		/* FALLTHROUGH */
	case GK_FWD_NEIGHBOR_BACK_NET:
		/*
		 * Do nothing because at this point we do not
		 * have a reference to @fib.
		 */
		break;

	default:
		rte_panic("Invalid FIB action (%u) at %s with lcore %u\n",
			fib->action, __func__, rte_lcore_id());
		break;
	}

	rte_atomic16_inc(&fib->num_updated_instances);
}

static void
process_gk_cmd(struct gk_cmd_entry *entry,
	struct gk_instance *instance, struct gk_config *gk_conf)
{
	switch (entry->op) {
	case GGU_POLICY_ADD:
		add_ggu_policy(&entry->u.ggu, instance, gk_conf);
		break;

	case GK_SYNCH_WITH_LPM:
		gk_synchronize(entry->u.fib, instance);
		break;

	case GK_FLUSH_FLOW_TABLE:
		flush_flow_table(&entry->u.flush.src,
			&entry->u.flush.dst, instance);
		break;

	default:
		GK_LOG(ERR, "Unknown command operation %u\n", entry->op);
		break;
	}
}

static int
gk_setup_rss(struct gk_config *gk_conf)
{
	int i, ret;

	if (gk_conf->net->front.rss) {
		uint16_t port_front = gk_conf->net->front.id;
		uint16_t gk_queues_front[gk_conf->num_lcores];

		for (i = 0; i < gk_conf->num_lcores; i++) {
			gk_queues_front[i] =
				gk_conf->instances[i].rx_queue_front;
		}

		ret = gatekeeper_setup_rss(port_front,
			gk_queues_front, gk_conf->num_lcores);
		if (ret < 0)
			goto out;

		ret = gatekeeper_get_rss_config(port_front,
			&gk_conf->rss_conf_front);
		if (ret < 0)
			goto out;
	}

	if (gk_conf->net->back.rss) {
		uint16_t port_back = gk_conf->net->back.id;
		uint16_t gk_queues_back[gk_conf->num_lcores];

		for (i = 0; i < gk_conf->num_lcores; i++) {
			gk_queues_back[i] =
				gk_conf->instances[i].rx_queue_back;
		}

		ret = gatekeeper_setup_rss(port_back,
			gk_queues_back, gk_conf->num_lcores);
		if (ret < 0)
			goto out;

		ret = gatekeeper_get_rss_config(port_back,
			&gk_conf->rss_conf_back);
		if (ret < 0)
			goto out;
	}

	ret = 0;

out:
	return ret;
}

static void
xmit_icmp(struct gatekeeper_if *iface, struct ipacket *packet,
	uint16_t *num_pkts, struct rte_mbuf **icmp_bufs,
	struct gk_instance *instance, packet_drop_cb_func cb_f)
{
	struct rte_ether_addr eth_addr_tmp;
	struct rte_ether_hdr *icmp_eth;
	struct rte_ipv4_hdr *icmp_ipv4;
	struct rte_icmp_hdr *icmph;
	struct rte_mbuf *pkt = packet->pkt;
	int icmp_pkt_len = iface->l2_len_out + sizeof(struct rte_ipv4_hdr) +
		sizeof(struct rte_icmp_hdr);
	if (pkt->data_len >= icmp_pkt_len) {
		int ret = rte_pktmbuf_trim(pkt, pkt->data_len - icmp_pkt_len);
		if (ret < 0) {
			GK_LOG(ERR,
				"Failed to remove %d bytes of data at the end of the mbuf at %s",
				pkt->data_len - icmp_pkt_len, __func__);
			cb_f(pkt, instance);
			return;
		}

		icmp_eth = rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);
	} else {
		icmp_eth = (struct rte_ether_hdr *)rte_pktmbuf_append(pkt,
			icmp_pkt_len - pkt->data_len);
		if (icmp_eth == NULL) {
			GK_LOG(ERR,
				"Failed to append %d bytes of new data: not enough headroom space in the first segment at %s\n",
				icmp_pkt_len - pkt->data_len, __func__);
			cb_f(pkt, instance);
			return;
		}
	}

	rte_ether_addr_copy(&icmp_eth->s_addr, &eth_addr_tmp);
	rte_ether_addr_copy(&icmp_eth->d_addr, &icmp_eth->s_addr);
	rte_ether_addr_copy(&eth_addr_tmp, &icmp_eth->d_addr);
	if (iface->vlan_insert) {
		fill_vlan_hdr(icmp_eth, iface->vlan_tag_be,
			RTE_ETHER_TYPE_IPV4);
	}

	icmp_ipv4 = (struct rte_ipv4_hdr *)pkt_out_skip_l2(iface, icmp_eth);
	icmp_ipv4->version_ihl = IP_VHL_DEF;
	icmp_ipv4->type_of_service = 0;
	icmp_ipv4->packet_id = 0;
	icmp_ipv4->fragment_offset = IP_DN_FRAGMENT_FLAG;
	icmp_ipv4->time_to_live = IP_DEFTTL;
	icmp_ipv4->next_proto_id = IPPROTO_ICMP;
	icmp_ipv4->src_addr = packet->flow.f.v4.dst.s_addr;
	icmp_ipv4->dst_addr = packet->flow.f.v4.src.s_addr;
	icmp_ipv4->total_length = rte_cpu_to_be_16(pkt->data_len -
		iface->l2_len_out);
	/*
	 * The IP header checksum filed must be set to 0
	 * in order to offload the checksum calculation.
	 */
	icmp_ipv4->hdr_checksum = 0;
	pkt->l2_len = iface->l2_len_out;
	pkt->l3_len = sizeof(struct rte_ipv4_hdr);
	pkt->ol_flags |= PKT_TX_IPV4 | PKT_TX_IP_CKSUM;

	icmph = (struct rte_icmp_hdr *)&icmp_ipv4[1];
	icmph->icmp_type = ICMP_TIME_EXCEEDED;
	icmph->icmp_code = ICMP_EXC_TTL;
	icmph->icmp_cksum = 0;
	icmph->icmp_ident = 0;
	icmph->icmp_seq_nb = 0;
	icmph->icmp_cksum = icmp_cksum(icmph, sizeof(*icmph));

	icmp_bufs[*num_pkts] = pkt;
	(*num_pkts)++;
}

static void
xmit_icmpv6(struct gatekeeper_if *iface, struct ipacket *packet,
	uint16_t *num_pkts, struct rte_mbuf **icmp_bufs,
	struct gk_instance *instance, packet_drop_cb_func cb_f)
{
	struct rte_ether_addr eth_addr_tmp;
	struct rte_ether_hdr *icmp_eth;
	struct rte_ipv6_hdr *icmp_ipv6;
	struct icmpv6_hdr *icmpv6_hdr;
	struct rte_mbuf *pkt = packet->pkt;
	int icmpv6_pkt_len = iface->l2_len_out + sizeof(struct rte_ipv6_hdr) +
		sizeof(struct icmpv6_hdr);
	if (pkt->data_len >= icmpv6_pkt_len) {
		int ret = rte_pktmbuf_trim(pkt,
			pkt->data_len - icmpv6_pkt_len);
		if (ret < 0) {
			GK_LOG(ERR,
				"Failed to remove %d bytes of data at the end of the mbuf at %s",
				pkt->data_len - icmpv6_pkt_len, __func__);
			cb_f(pkt, instance);
			return;
		}

		icmp_eth = rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);
	} else {
		icmp_eth = (struct rte_ether_hdr *)rte_pktmbuf_append(pkt,
			icmpv6_pkt_len - pkt->data_len);
		if (icmp_eth == NULL) {
			GK_LOG(ERR,
				"Failed to append %d bytes of new data: not enough headroom space in the first segment at %s\n",
				icmpv6_pkt_len - pkt->data_len, __func__);
			cb_f(pkt, instance);
			return;
		}
	}

	rte_ether_addr_copy(&icmp_eth->s_addr, &eth_addr_tmp);
	rte_ether_addr_copy(&icmp_eth->d_addr, &icmp_eth->s_addr);
	rte_ether_addr_copy(&eth_addr_tmp, &icmp_eth->d_addr);
	if (iface->vlan_insert) {
		fill_vlan_hdr(icmp_eth, iface->vlan_tag_be,
			RTE_ETHER_TYPE_IPV6);
	}

	/* Set-up IPv6 header. */
	icmp_ipv6 = (struct rte_ipv6_hdr *)pkt_out_skip_l2(iface, icmp_eth);
	icmp_ipv6->vtc_flow = rte_cpu_to_be_32(IPv6_DEFAULT_VTC_FLOW);
	icmp_ipv6->payload_len = rte_cpu_to_be_16(sizeof(*icmpv6_hdr));
	icmp_ipv6->proto = IPPROTO_ICMPV6;
	/*
	 * The IP Hop Limit field must be 255 as required by
	 * RFC 4861, sections 7.1.1 and 7.1.2.
	 */
	icmp_ipv6->hop_limits = 255;
	rte_memcpy(icmp_ipv6->src_addr, packet->flow.f.v6.dst.s6_addr,
		sizeof(icmp_ipv6->src_addr));
	rte_memcpy(icmp_ipv6->dst_addr, packet->flow.f.v6.src.s6_addr,
		sizeof(icmp_ipv6->dst_addr));

	/* Set-up ICMPv6 header. */
	icmpv6_hdr = (struct icmpv6_hdr *)&icmp_ipv6[1];
	icmpv6_hdr->type = ICMPV6_TIME_EXCEED;
	icmpv6_hdr->code = ICMPV6_EXC_HOPLIMIT;
	icmpv6_hdr->cksum = 0; /* Calculated below. */

	icmpv6_hdr->cksum = rte_ipv6_icmpv6_cksum(icmp_ipv6, icmpv6_hdr);

	icmp_bufs[*num_pkts] = pkt;
	(*num_pkts)++;
}

/*
 * For IPv4, according to the RFC 1812 section 5.3.1 Time to Live (TTL),
 * if the TTL is reduced to zero (or less), the packet MUST be
 * discarded, and if the destination is not a multicast address the
 * router MUST send an ICMP Time Exceeded message, Code 0 (TTL Exceeded
 * in Transit) message to the source.
 *
 * For IPv6, according to the RFC 1883 section 4.4,
 * if the IPv6 Hop Limit is less than or equal to 1, then the router needs to
 * send an ICMP Time Exceeded -- Hop Limit Exceeded in Transit message to
 * the Source Address and discard the packet.
 */
static int
update_ip_hop_count(struct gatekeeper_if *iface, struct ipacket *packet,
	uint16_t *num_pkts, struct rte_mbuf **icmp_bufs,
	struct token_bucket_ratelimit_state *rs, struct gk_instance *instance,
	packet_drop_cb_func cb_f)
{
	if (packet->flow.proto == RTE_ETHER_TYPE_IPV4) {
		struct rte_ipv4_hdr *ipv4_hdr = packet->l3_hdr;
		if (ipv4_hdr->time_to_live <= 1) {
			if (tb_ratelimit_allow(rs)) {
				xmit_icmp(iface, packet, num_pkts,
					icmp_bufs, instance, cb_f);
			} else
				cb_f(packet->pkt, instance);
			return -ETIMEDOUT;
		}

		--(ipv4_hdr->time_to_live);
		++(ipv4_hdr->hdr_checksum);
	} else if (likely(packet->flow.proto == RTE_ETHER_TYPE_IPV6)) {
		struct rte_ipv6_hdr *ipv6_hdr = packet->l3_hdr;
		if (ipv6_hdr->hop_limits <= 1) {
			if (tb_ratelimit_allow(rs)) {
				xmit_icmpv6(iface, packet, num_pkts,
					icmp_bufs, instance, cb_f);
			} else
				cb_f(packet->pkt, instance);
			return -ETIMEDOUT;
		}

		--(ipv6_hdr->hop_limits);
	} else {
		GK_LOG(WARNING,
			"Unexpected condition at %s: unknown flow type %hu\n",
			__func__, packet->flow.proto);
		cb_f(packet->pkt, instance);
		return -EINVAL;
	}

	return 0;
}

/* Process the packets on the front interface. */
static void
process_pkts_front(uint16_t port_front, uint16_t port_back,
	uint16_t rx_queue_front, uint16_t tx_queue_back,
	unsigned int lcore, uint16_t *num_pkts, struct rte_mbuf **icmp_bufs,
	struct gk_instance *instance, struct gk_config *gk_conf)
{
	/* Get burst of RX packets, from first port of pair. */
	int i;
	int ret;
	uint16_t num_rx;
	uint16_t num_tx = 0;
	uint16_t num_tx_succ;
	uint16_t num_arp = 0;
	uint16_t front_max_pkt_burst = gk_conf->front_max_pkt_burst;
	struct rte_mbuf *rx_bufs[front_max_pkt_burst];
	struct rte_mbuf *tx_bufs[front_max_pkt_burst];
	struct rte_mbuf *arp_bufs[front_max_pkt_burst];
	struct acl_search *acl4 = instance->acl4;
	struct acl_search *acl6 = instance->acl6;
	struct gatekeeper_if *front = &gk_conf->net->front;
	struct gatekeeper_if *back = &gk_conf->net->back;
	struct gk_measurement_metrics *stats = &instance->traffic_stats;
	bool ipv4_configured_front = ipv4_if_configured(&gk_conf->net->front);
	bool ipv6_configured_front = ipv6_if_configured(&gk_conf->net->front);

	/* Load a set of packets from the front NIC. */
	num_rx = rte_eth_rx_burst(port_front, rx_queue_front, rx_bufs,
		front_max_pkt_burst);

	if (unlikely(num_rx == 0))
		return;

	stats->tot_pkts_num += num_rx;

	for (i = 0; i < num_rx; i++) {
		struct ipacket packet;
		/*
		 * Pointer to the flow entry in request state 
		 * under evaluation.
		 */
		struct flow_entry *fe;
		struct rte_mbuf *pkt = rx_bufs[i];
		uint32_t ip_flow_hash_val;

		stats->tot_pkts_size += rte_pktmbuf_pkt_len(pkt);

		ret = extract_packet_info(pkt, &packet);
		if (ret < 0) {
			if (likely(packet.flow.proto == RTE_ETHER_TYPE_ARP)) {
				stats->tot_pkts_num_distributed++;
				stats->tot_pkts_size_distributed +=
					rte_pktmbuf_pkt_len(pkt);

				arp_bufs[num_arp++] = pkt;
				continue;
			}

			/* Drop non-IP and non-ARP packets. */
			drop_packet_front(pkt, instance);
			continue;
		}

		if (unlikely((packet.flow.proto == RTE_ETHER_TYPE_IPV4 &&
				!ipv4_configured_front) ||
				(packet.flow.proto == RTE_ETHER_TYPE_IPV6 &&
				!ipv6_configured_front))) {
			drop_packet_front(pkt, instance);
			continue;
		}

		ip_flow_hash_val = likely(front->rss) ? pkt->hash.rss :
			rss_ip_flow_hf(&packet.flow, 0, 0);

		/* 
		 * Find the flow entry for the IP pair.
		 *
		 * If the pair of source and destination addresses 
		 * is in the flow table, proceed as the entry instructs,
		 * and go to the next packet.
		 */
		ret = rte_hash_lookup_with_hash(instance->ip_flow_hash_table,
			&packet.flow, ip_flow_hash_val);
		if (ret >= 0)
			fe = &instance->ip_flow_entry_table[ret];
		else {
			/*
			 * Otherwise, look up the destination address
		 	 * in the global LPM table.
			 */
			struct gk_fib *fib = look_up_fib(
				&gk_conf->lpm_tbl, &packet.flow);
			struct ether_cache *eth_cache;

			if (fib == NULL || fib->action == GK_FWD_NEIGHBOR_FRONT_NET) {
				if (packet.flow.proto == RTE_ETHER_TYPE_IPV4) {
					stats->tot_pkts_num_distributed++;
					stats->tot_pkts_size_distributed +=
						rte_pktmbuf_pkt_len(pkt);

					add_pkt_acl(acl4, pkt);
				} else if (likely(packet.flow.proto ==
						RTE_ETHER_TYPE_IPV6)) {
					stats->tot_pkts_num_distributed++;
					stats->tot_pkts_size_distributed +=
						rte_pktmbuf_pkt_len(pkt);

					add_pkt_acl(acl6, pkt);
				} else {
					print_flow_err_msg(&packet.flow,
						"gk: failed to get the fib entry");
					drop_packet_front(pkt, instance);
				}
				continue;
			}

			switch (fib->action) {
			case GK_FWD_GRANTOR:
				/*
				 * We heuristically drop entries to
				 * alleviate memory pressure
				 * when the table is full.
				 *
				 * The entry instructs to enforce
				 * policies over its packets,
			 	 * initialize an entry in the
				 * flow table, proceed as the
				 * brand-new entry instructs, and
			 	 * go to the next packet.
			 	 */
				ret = gk_hash_add_flow_entry(
					instance, &packet.flow,
					gk_conf->request_timeout_cycles,
					ip_flow_hash_val, GK_REQUEST);
				if (ret == -ENOSPC) {
					/*
					 * There is no room for a new
					 * flow entry, but give this
					 * flow a chance sending a
					 * request to the grantor
					 * server.
					 */
					struct flow_entry temp_fe;
					initialize_flow_entry(&temp_fe,
						&packet.flow, fib);
					ret = gk_process_request(
						&temp_fe, &packet,
						gk_conf->sol_conf, stats);
					if (ret < 0) {
						drop_packet_front(
							pkt, instance);
					}
					continue;
				} else if (ret < 0) {
					drop_packet_front(pkt, instance);
					continue;
				}

				fe = &instance->ip_flow_entry_table[ret];
				initialize_flow_entry(fe, &packet.flow, fib);
				break;

			case GK_FWD_GATEWAY_BACK_NET: {
			 	/*
				 * The entry instructs to forward
				 * its packets to the gateway in
				 * the back network, forward accordingly.
				 *
				 * BP block bypasses from the front to the
				 * back interface are expected to bypass
				 * ranges of IP addresses that should not
				 * go through Gatekeeper.
				 *
				 * Notice that one needs to update
				 * the Ethernet header.
				 */

				eth_cache = fib->u.gateway.eth_cache;
				RTE_VERIFY(eth_cache != NULL);

				if (adjust_pkt_len(pkt, back, 0) == NULL ||
						pkt_copy_cached_eth_header(pkt,
							eth_cache,
							back->l2_len_out)) {
					drop_packet_front(pkt, instance);
					continue;
				}

				if (update_ip_hop_count(front, &packet,
						num_pkts, icmp_bufs,
						&instance->front_icmp_rs,
						instance,
						drop_packet_front) < 0)
					continue;

				tx_bufs[num_tx++] = pkt;
				continue;
			}

			case GK_FWD_NEIGHBOR_BACK_NET: {
				/*
				 * The entry instructs to forward
				 * its packets to the neighbor in
				 * the back network, forward accordingly.
				 */
				if (packet.flow.proto == RTE_ETHER_TYPE_IPV4) {
					eth_cache = lookup_ether_cache(
						&fib->u.neigh,
						&packet.flow.f.v4.dst);
				} else {
					eth_cache = lookup_ether_cache(
						&fib->u.neigh6,
						&packet.flow.f.v6.dst);
				}

				RTE_VERIFY(eth_cache != NULL);

				if (adjust_pkt_len(pkt, back, 0) == NULL ||
						pkt_copy_cached_eth_header(pkt,
							eth_cache,
							back->l2_len_out)) {
					drop_packet_front(pkt, instance);
					continue;
				}

				if (update_ip_hop_count(front, &packet,
						num_pkts, icmp_bufs,
						&instance->front_icmp_rs,
						instance,
						drop_packet_front) < 0)
					continue;

				tx_bufs[num_tx++] = pkt;
				continue;
			}

			case GK_DROP:
				/* FALLTHROUGH */
			default:
				drop_packet_front(pkt, instance);
				continue;
			}
		}

		switch (fe->state) {
		case GK_REQUEST:
			ret = gk_process_request(fe, &packet,
				gk_conf->sol_conf, stats);
			break;

		case GK_GRANTED:
			ret = gk_process_granted(fe, &packet,
				gk_conf->sol_conf, stats);
			break;

		case GK_DECLINED:
			ret = gk_process_declined(fe, &packet,
				gk_conf->sol_conf, stats);
			break;

		case GK_BPF:
			ret = gk_process_bpf(fe, &packet, gk_conf, stats);
			break;

		default:
			ret = -1;
			GK_LOG(ERR, "Unknown flow state: %d\n", fe->state);
			break;
		}

		if (ret < 0)
			drop_packet_front(pkt, instance);
		else if (ret == EINPROGRESS) {
			/* Request will be serviced by another lcore. */
			continue;
		} else if (likely(ret == 0))
			tx_bufs[num_tx++] = pkt;
		else
			rte_panic("Invalid return value (%d) from processing a packet in a flow with state %d",
				ret, fe->state);
	}

	/* Send burst of TX packets, to second port of pair. */
	num_tx_succ = rte_eth_tx_burst(port_back, tx_queue_back,
		tx_bufs, num_tx);

	/* XXX #71 Do something better here! For now, free any unsent packets. */
	if (unlikely(num_tx_succ < num_tx)) {
		for (i = num_tx_succ; i < num_tx; i++)
			drop_packet_front(tx_bufs[i], instance);
	}

	if (num_arp > 0)
		submit_arp(arp_bufs, num_arp, &gk_conf->net->front);

	process_pkts_acl(&gk_conf->net->front,
		lcore, acl4, RTE_ETHER_TYPE_IPV4);
	process_pkts_acl(&gk_conf->net->front,
		lcore, acl6, RTE_ETHER_TYPE_IPV6);
}

/* Process the packets on the back interface. */
static void
process_pkts_back(uint16_t port_back, uint16_t port_front,
	uint16_t rx_queue_back, uint16_t tx_queue_front,
	unsigned int lcore, uint16_t *num_pkts, struct rte_mbuf **icmp_bufs,
	struct gk_instance *instance, struct gk_config *gk_conf)
{
	/* Get burst of RX packets, from first port of pair. */
	int i;
	int ret;
	uint16_t num_rx;
	uint16_t num_tx = 0;
	uint16_t num_tx_succ;
	uint16_t num_arp = 0;
	uint16_t back_max_pkt_burst = gk_conf->back_max_pkt_burst;
	struct rte_mbuf *rx_bufs[back_max_pkt_burst];
	struct rte_mbuf *tx_bufs[back_max_pkt_burst];
	struct rte_mbuf *arp_bufs[back_max_pkt_burst];
	struct acl_search *acl4 = instance->acl4;
	struct acl_search *acl6 = instance->acl6;
	struct gatekeeper_if *front = &gk_conf->net->front;
	struct gatekeeper_if *back = &gk_conf->net->back;
	bool ipv4_configured_back = ipv4_if_configured(&gk_conf->net->back);
	bool ipv6_configured_back = ipv6_if_configured(&gk_conf->net->back);

	/* Load a set of packets from the back NIC. */
	num_rx = rte_eth_rx_burst(port_back, rx_queue_back, rx_bufs,
		back_max_pkt_burst);

	if (unlikely(num_rx == 0))
		return;

	for (i = 0; i < num_rx; i++) {
		struct ipacket packet;
		struct gk_fib *fib;
		struct rte_mbuf *pkt = rx_bufs[i];
		struct ether_cache *eth_cache;

		ret = extract_packet_info(pkt, &packet);
		if (ret < 0) {
			if (likely(packet.flow.proto == RTE_ETHER_TYPE_ARP)) {
				arp_bufs[num_arp++] = pkt;
				continue;
			}

			/* Drop non-IP and non-ARP packets. */
			drop_packet(pkt);
			continue;
		}

		if (unlikely((packet.flow.proto == RTE_ETHER_TYPE_IPV4 &&
				!ipv4_configured_back) ||
				(packet.flow.proto == RTE_ETHER_TYPE_IPV6 &&
				!ipv6_configured_back))) {
			drop_packet_back(pkt, instance);
			continue;
		}

		fib = look_up_fib(&gk_conf->lpm_tbl, &packet.flow);
		if (fib == NULL || fib->action == GK_FWD_NEIGHBOR_BACK_NET) {
			if (packet.flow.proto == RTE_ETHER_TYPE_IPV4)
				add_pkt_acl(acl4, pkt);
			else if (likely(packet.flow.proto ==
					RTE_ETHER_TYPE_IPV6))
				add_pkt_acl(acl6, pkt);
			else {
				print_flow_err_msg(&packet.flow,
					"gk: failed to get the fib entry or it is not an IP packet");
				drop_packet(pkt);
			}
			continue;
		}

		switch (fib->action) {
		case GK_FWD_GATEWAY_FRONT_NET: {
			/*
			 * The entry instructs to forward
			 * its packets to the gateway in
			 * the front network, forward accordingly.
			 *
			 * BP bypasses from the back to the front interface
			 * are expected to bypass the outgoing traffic
			 * from the AS to its peers.
			 *
			 * Notice that one needs to update
			 * the Ethernet header.
			 */
			eth_cache = fib->u.gateway.eth_cache;
			RTE_VERIFY(eth_cache != NULL);

			if (adjust_pkt_len(pkt, front, 0) == NULL ||
					pkt_copy_cached_eth_header(pkt,
						eth_cache,
						front->l2_len_out)) {
				drop_packet(pkt);
				continue;
			}

			if (update_ip_hop_count(back, &packet,
					num_pkts, icmp_bufs,
					&instance->back_icmp_rs,
					instance, drop_packet_back) < 0)
				continue;

			tx_bufs[num_tx++] = pkt;
			continue;
		}

		case GK_FWD_NEIGHBOR_FRONT_NET: {
			/*
		 	 * The entry instructs to forward
			 * its packets to the neighbor in
			 * the front network, forward accordingly.
			 */
			if (packet.flow.proto == RTE_ETHER_TYPE_IPV4) {
				eth_cache = lookup_ether_cache(
					&fib->u.neigh,
					&packet.flow.f.v4.dst);
			} else {
				eth_cache = lookup_ether_cache(
					&fib->u.neigh6,
					&packet.flow.f.v6.dst);
			}

			RTE_VERIFY(eth_cache != NULL);

			if (adjust_pkt_len(pkt, front, 0) == NULL ||
					pkt_copy_cached_eth_header(pkt,
						eth_cache,
						front->l2_len_out)) {
				drop_packet(pkt);
				continue;
			}

			if (update_ip_hop_count(back, &packet,
					num_pkts, icmp_bufs,
					&instance->back_icmp_rs,
					instance, drop_packet_back) < 0)
				continue;

			tx_bufs[num_tx++] = pkt;
			continue;
		}

		case GK_DROP:
			drop_packet(pkt);
			continue;

		default:
			/* All other actions should log a warning. */
			GK_LOG(WARNING,
				"The fib entry has an unexpected action %u at %s\n",
				fib->action, __func__);
			drop_packet(pkt);
			continue;
		}
	}

	/* Send burst of TX packets, to second port of pair. */
	num_tx_succ = rte_eth_tx_burst(port_front, tx_queue_front,
		tx_bufs, num_tx);

	/* XXX #71 Do something better here! For now, free any unsent packets. */
	if (unlikely(num_tx_succ < num_tx)) {
		for (i = num_tx_succ; i < num_tx; i++)
			drop_packet(tx_bufs[i]);
	}

	if (num_arp > 0)
		submit_arp(arp_bufs, num_arp, &gk_conf->net->back);

	process_pkts_acl(&gk_conf->net->back, lcore, acl4, RTE_ETHER_TYPE_IPV4);
	process_pkts_acl(&gk_conf->net->back, lcore, acl6, RTE_ETHER_TYPE_IPV6);
}

static void
process_cmds_from_mailbox(
	struct gk_instance *instance, struct gk_config *gk_conf)
{
	int i;
	int num_cmd;
	unsigned int mailbox_burst_size = gk_conf->mailbox_burst_size;
	struct gk_cmd_entry *gk_cmds[mailbox_burst_size];

	/* Load a set of commands from its mailbox ring. */
        num_cmd = mb_dequeue_burst(&instance->mb,
		(void **)gk_cmds, mailbox_burst_size);

        for (i = 0; i < num_cmd; i++) {
		process_gk_cmd(gk_cmds[i], instance, gk_conf);
		mb_free_entry(&instance->mb, gk_cmds[i]);
        }
}

static int
gk_proc(void *arg)
{
	unsigned int lcore = rte_lcore_id();
	struct gk_config *gk_conf = (struct gk_config *)arg;
	unsigned int block_idx = get_block_idx(gk_conf, lcore);
	struct gk_instance *instance = &gk_conf->instances[block_idx];

	uint16_t port_front = get_net_conf()->front.id;
	uint16_t port_back = get_net_conf()->back.id;
	uint16_t rx_queue_front = instance->rx_queue_front;
	uint16_t tx_queue_front = instance->tx_queue_front;
	uint16_t rx_queue_back = instance->rx_queue_back;
	uint16_t tx_queue_back = instance->tx_queue_back;

	uint16_t front_num_pkts;
	uint16_t back_num_pkts;
	struct rte_mbuf *front_icmp_bufs[gk_conf->front_max_pkt_burst];
	struct rte_mbuf *back_icmp_bufs[gk_conf->back_max_pkt_burst];

	int num_buckets = rte_hash_get_num_buckets(
		instance->ip_flow_hash_table);
	uint32_t bucket_idx = 0;
	uint64_t last_scan_tsc = rte_rdtsc();
	uint64_t last_measure_tsc = last_scan_tsc;
	uint64_t basic_measurement_logging_cycles =
		gk_conf->basic_measurement_logging_ms *
		rte_get_tsc_hz() / 1000;
	uint64_t bucket_scan_timeout_cycles = round(
		(double)(gk_conf->flow_table_full_scan_ms *
		rte_get_tsc_hz()) / (num_buckets * 1000.));
	if (bucket_scan_timeout_cycles == 0) {
		GK_LOG(WARNING,
			"The value of the field flow_table_full_scan_ms in Gatekeeper configuration is too small\n");
		exiting = true;
		return -1;
	}

	GK_LOG(NOTICE, "The GK block is running at lcore = %u\n", lcore);

	gk_conf_hold(gk_conf);

	while (likely(!exiting)) {
		uint64_t now;

		front_num_pkts = 0;
		back_num_pkts = 0;

		process_pkts_front(port_front, port_back,
			rx_queue_front, tx_queue_back,
			lcore, &front_num_pkts, front_icmp_bufs,
			instance, gk_conf);

		process_pkts_back(port_back, port_front,
			rx_queue_back, tx_queue_front, lcore,
			&back_num_pkts, back_icmp_bufs, instance, gk_conf);

		send_pkts(port_front, rx_queue_front,
			front_num_pkts, front_icmp_bufs);

		send_pkts(port_back, rx_queue_back,
			back_num_pkts, back_icmp_bufs);

		process_cmds_from_mailbox(instance, gk_conf);

		now = rte_rdtsc();
		if (now - last_scan_tsc >= bucket_scan_timeout_cycles) {
			gk_flow_tbl_bucket_scan(&bucket_idx,
				gk_conf->request_timeout_cycles, instance);
			last_scan_tsc = rte_rdtsc();
			now = last_scan_tsc;
		}

		if (now - last_measure_tsc >=
				basic_measurement_logging_cycles) {
			struct gk_measurement_metrics *stats =
				&instance->traffic_stats;

			GK_LOG(NOTICE,
				"The GK block basic measurements at lcore = %u: [tot_pkts_num = %"PRIu64", tot_pkts_size = %"PRIu64", pkts_num_granted = %"PRIu64", pkts_size_granted = %"PRIu64", pkts_num_request = %"PRIu64", pkts_size_request =  %"PRIu64", pkts_num_declined = %"PRIu64", pkts_size_declined =  %"PRIu64", tot_pkts_num_dropped = %"PRIu64", tot_pkts_size_dropped =  %"PRIu64", tot_pkts_num_distributed = %"PRIu64", tot_pkts_size_distributed =  %"PRIu64"]\n",
				lcore, stats->tot_pkts_num,
				stats->tot_pkts_size,
				stats->pkts_num_granted,
				stats->pkts_size_granted,
				stats->pkts_num_request,
				stats->pkts_size_request,
				stats->pkts_num_declined,
				stats->pkts_size_declined,
				stats->tot_pkts_num_dropped,
				stats->tot_pkts_size_dropped,
				stats->tot_pkts_num_distributed,
				stats->tot_pkts_size_distributed);

			memset(stats, 0, sizeof(*stats));

			last_measure_tsc = rte_rdtsc();
		}
	}

	GK_LOG(NOTICE, "The GK block at lcore = %u is exiting\n", lcore);

	return gk_conf_put(gk_conf);
}

struct gk_config *
alloc_gk_conf(void)
{
	return rte_calloc("gk_config", 1, sizeof(struct gk_config), 0);
}

void
set_gk_request_timeout(unsigned int request_timeout_sec,
	struct gk_config *gk_conf)
{
	gk_conf->request_timeout_cycles =
		request_timeout_sec * rte_get_tsc_hz();
}

static void
destroy_gk_lpm(struct gk_lpm *ltbl)
{
	destroy_ipv4_lpm(ltbl->lpm);
	ltbl->lpm = NULL;
	rte_free(ltbl->fib_tbl);
	ltbl->fib_tbl = NULL;

	destroy_ipv6_lpm(ltbl->lpm6);
	ltbl->lpm6 = NULL;
	rte_free(ltbl->fib_tbl6);
	ltbl->fib_tbl6 = NULL;
}

static int
cleanup_gk(struct gk_config *gk_conf)
{
	int i;
	unsigned int ui;

	for (i = 0; i < gk_conf->num_lcores; i++) {
		if (gk_conf->instances[i].ip_flow_hash_table != NULL) {
			rte_hash_free(gk_conf->instances[i].
				ip_flow_hash_table);
		}

		if (gk_conf->instances[i].ip_flow_entry_table != NULL) {
			rte_free(gk_conf->instances[i].
				ip_flow_entry_table);
		}

		if (gk_conf->instances[i].acl4 != NULL)
			destroy_acl_search(gk_conf->instances[i].acl4);
		if (gk_conf->instances[i].acl6 != NULL)
			destroy_acl_search(gk_conf->instances[i].acl6);

		destroy_mailbox(&gk_conf->instances[i].mb);
	}

	if (gk_conf->lpm_tbl.fib_tbl != NULL) {
		for (ui = 0; ui < gk_conf->max_num_ipv4_fib_entries; ui++) {
			struct gk_fib *fib = &gk_conf->lpm_tbl.fib_tbl[ui];
			if (fib->action == GK_FWD_NEIGHBOR_FRONT_NET ||
					fib->action ==
						GK_FWD_NEIGHBOR_BACK_NET) {
				destroy_neigh_hash_table(&fib->u.neigh);
			}
		}
	}

	if (gk_conf->lpm_tbl.fib_tbl6 != NULL) {
		for (ui = 0; ui < gk_conf->max_num_ipv6_fib_entries; ui++) {
			struct gk_fib *fib = &gk_conf->lpm_tbl.fib_tbl6[ui];
			if (fib->action == GK_FWD_NEIGHBOR_FRONT_NET ||
					fib->action ==
						GK_FWD_NEIGHBOR_BACK_NET) {
				destroy_neigh_hash_table(&fib->u.neigh6);
			}
		}
	}

	destroy_gk_lpm(&gk_conf->lpm_tbl);

	rte_free(gk_conf->queue_id_to_instance);
	rte_free(gk_conf->instances);
	rte_free(gk_conf->lcores);
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

static int
gk_stage1(void *arg)
{
	struct gk_config *gk_conf = arg;
	int num_rx_queues = gk_conf->net->front.num_rx_queues;
	int ret, i;

	gk_conf->instances = rte_calloc(__func__, gk_conf->num_lcores,
		sizeof(struct gk_instance), 0);
	if (gk_conf->instances == NULL)
		goto cleanup;

	gk_conf->queue_id_to_instance = rte_malloc(__func__,
		num_rx_queues * sizeof(*gk_conf->queue_id_to_instance), 0);
	if (gk_conf->queue_id_to_instance == NULL)
		goto cleanup;

	for(i = 0; i < num_rx_queues; i++)
		gk_conf->queue_id_to_instance[i] = -1;

	/*
	 * Set up the GK LPM table. We assume that
	 * all the GK instances are running on the same socket.
	 */
	ret = setup_gk_lpm(gk_conf,
		rte_lcore_to_socket_id(gk_conf->lcores[0]));
	if (ret < 0)
		goto cleanup;

	for (i = 0; i < gk_conf->num_lcores; i++) {
		unsigned int lcore = gk_conf->lcores[i];
		struct gk_instance *inst_ptr = &gk_conf->instances[i];

		/* Set up queue identifiers for RSS. */

		ret = get_queue_id(&gk_conf->net->front, QUEUE_TYPE_RX, lcore);
		if (ret < 0) {
			GK_LOG(ERR, "Cannot assign an RX queue for the front interface for lcore %u\n",
				lcore);
			goto cleanup;
		}
		inst_ptr->rx_queue_front = ret;
		gk_conf->queue_id_to_instance[ret] = i;

		ret = get_queue_id(&gk_conf->net->front, QUEUE_TYPE_TX, lcore);
		if (ret < 0) {
			GK_LOG(ERR, "Cannot assign a TX queue for the front interface for lcore %u\n",
				lcore);
			goto cleanup;
		}
		inst_ptr->tx_queue_front = ret;

		ret = get_queue_id(&gk_conf->net->back, QUEUE_TYPE_RX, lcore);
		if (ret < 0) {
			GK_LOG(ERR, "Cannot assign an RX queue for the back interface for lcore %u\n",
				lcore);
			goto cleanup;
		}
		inst_ptr->rx_queue_back = ret;

		ret = get_queue_id(&gk_conf->net->back, QUEUE_TYPE_TX, lcore);
		if (ret < 0) {
			GK_LOG(ERR, "Cannot assign a TX queue for the back interface for lcore %u\n",
				lcore);
			goto cleanup;
		}
		inst_ptr->tx_queue_back = ret;

		/* Setup the GK instance at @lcore. */
		ret = setup_gk_instance(lcore, gk_conf);
		if (ret < 0) {
			GK_LOG(ERR,
				"Failed to setup gk instances for GK block at lcore %u\n",
				lcore);
			goto cleanup;
		}
	}

	return 0;

cleanup:
	cleanup_gk(gk_conf);
	return -1;
}

static int
gk_stage2(void *arg)
{
	struct gk_config *gk_conf = arg;

	int ret = gk_setup_rss(gk_conf);
	if (ret < 0)
		goto cleanup;

	return 0;

cleanup:
	cleanup_gk(gk_conf);
	return ret;
}

int
run_gk(struct net_config *net_conf, struct gk_config *gk_conf,
	struct sol_config *sol_conf)
{
	int ret, i;
	uint16_t front_inc, back_inc;

	if (net_conf == NULL || gk_conf == NULL || sol_conf == NULL) {
		ret = -1;
		goto out;
	}

	gk_logtype = rte_log_register("gatekeeper.gk");
	if (gk_logtype < 0) {
		ret = -1;
		goto out;
	}
	ret = rte_log_set_level(gk_logtype, gk_conf->log_level);
	if (ret < 0) {
		ret = -1;
		goto out;
	}
	gk_conf->log_type = gk_logtype;

	for (i = 0; i < gk_conf->num_lcores; i++) {
		log_ratelimit_state_init(gk_conf->lcores[i],
			gk_conf->log_ratelimit_interval_ms,
			gk_conf->log_ratelimit_burst);
	}

	if (!net_conf->back_iface_enabled) {
		GK_LOG(ERR, "Back interface is required\n");
		ret = -1;
		goto out;
	}

	if (!ipv4_configured(net_conf) &&
			gk_conf->max_num_ipv4_fib_entries != 0) {
		GK_LOG(ERR,
			"IPv4 is not configured, but the number of FIB entries for IPv4 is non-zero %u\n",
			gk_conf->max_num_ipv4_fib_entries);
		ret = -1;
		goto out;
	}

	if (!ipv6_configured(net_conf) &&
			gk_conf->max_num_ipv6_fib_entries != 0) {
		GK_LOG(ERR,
			"IPv6 is not configured, but the number of FIB entries for IPv6 is non-zero %u\n",
			gk_conf->max_num_ipv6_fib_entries);
		ret = -1;
		goto out;
	}

	if (!(gk_conf->front_max_pkt_burst > 0 &&
			gk_conf->back_max_pkt_burst > 0)) {
		ret = -1;
		goto out;
	}

	front_inc = gk_conf->front_max_pkt_burst * gk_conf->num_lcores;
	net_conf->front.total_pkt_burst += front_inc;
	back_inc = gk_conf->back_max_pkt_burst * gk_conf->num_lcores;
	net_conf->back.total_pkt_burst += back_inc;

	gk_conf->net = net_conf;
	gk_conf->sol_conf = sol_conf;

	if (gk_conf->num_lcores <= 0)
		goto success;

	ret = net_launch_at_stage1(
		net_conf, gk_conf->num_lcores, gk_conf->num_lcores,
		gk_conf->num_lcores, gk_conf->num_lcores, gk_stage1, gk_conf);
	if (ret < 0)
		goto burst;

	ret = launch_at_stage2(gk_stage2, gk_conf);
	if (ret < 0)
		goto stage1;

	for (i = 0; i < gk_conf->num_lcores; i++) {
		unsigned int lcore = gk_conf->lcores[i];
		ret = launch_at_stage3("gk", gk_proc, gk_conf, lcore);
		if (ret < 0) {
			pop_n_at_stage3(i);
			goto stage2;
		}
	}

	goto success;

stage2:
	pop_n_at_stage2(1);
stage1:
	pop_n_at_stage1(1);
burst:
	net_conf->front.total_pkt_burst -= front_inc;
	net_conf->back.total_pkt_burst -= back_inc;
out:
	return ret;

success:
	rte_atomic32_init(&gk_conf->ref_cnt);
	return 0;
}

struct mailbox *
get_responsible_gk_mailbox(const struct ip_flow *flow,
	const struct gk_config *gk_conf)
{
	/*
	 * Calculate the RSS hash value for the
	 * pair <Src, Dst> in the decision.
	 */
	uint32_t rss_hash_val;
	uint32_t idx;
	uint32_t shift;
	uint16_t queue_id;
	int block_idx;

	if (unlikely(!gk_conf->net->front.rss)) {
		block_idx = 0;
		goto done;
	}

	RTE_VERIFY(gk_conf->rss_conf_front.reta_size > 0);
	rss_hash_val = rss_ip_flow_hf(flow, 0, 0) %
		gk_conf->rss_conf_front.reta_size;

	/*
	 * Identify which GK block is responsible for the
	 * pair <Src, Dst> in the decision.
	 */
	idx = rss_hash_val / RTE_RETA_GROUP_SIZE;
	shift = rss_hash_val % RTE_RETA_GROUP_SIZE;
	queue_id = gk_conf->rss_conf_front.reta_conf[idx].reta[shift];
	block_idx = gk_conf->queue_id_to_instance[queue_id];

	if (block_idx == -1)
		GK_LOG(ERR, "Wrong RSS configuration for GK blocks\n");
done:
	return &gk_conf->instances[block_idx].mb;
}

int
gk_flush_flow_table(const char *src_prefix,
	const char *dst_prefix, struct gk_config *gk_conf)
{
	int i;
	uint16_t proto = 0;
	struct gk_flush_request flush;

	if (src_prefix == NULL && dst_prefix == NULL) {
		GK_LOG(ERR, "Failed to flush flow table: both source and destination prefixes are NULL\n");
		return -1;
	}

	memset(&flush, 0, sizeof(flush));

	/*
	 * Field .str is only meant to help logging and debugging,
	 * but we cannot pass src_prefix or dst_prefix along
	 * because they go away soon after this function returns.
	 */
	flush.src.str = __func__;
	flush.dst.str = __func__;

	if (src_prefix != NULL) {
		flush.src.len = parse_ip_prefix(src_prefix,
			&flush.src.addr);
		if (flush.src.len < 0)
			return -1;
		proto = flush.src.addr.proto;
	}

	if (dst_prefix != NULL) {
		flush.dst.len = parse_ip_prefix(dst_prefix,
			&flush.dst.addr);
		if (flush.dst.len < 0 || (src_prefix != NULL &&
				flush.dst.addr.proto != proto))
			return -1;
		proto = flush.dst.addr.proto;
	}

	if (src_prefix == NULL)
		flush.src.addr.proto = proto;
	if (dst_prefix == NULL)
		flush.dst.addr.proto = proto;

	for (i = 0; i < gk_conf->num_lcores; i++) {
		struct gk_cmd_entry *entry =
			mb_alloc_entry(&gk_conf->instances[i].mb);
		if (entry == NULL) {
			GK_LOG(WARNING,
				"Cannot allocate an entry for the mailbox of the GK block at lcore %u to flush flows that match src_prefix=%s and dst_prefix=%s\n",
				gk_conf->lcores[i], src_prefix, dst_prefix);
			continue;
		}

		entry->op = GK_FLUSH_FLOW_TABLE;
		entry->u.flush = flush;

		mb_send_entry(&gk_conf->instances[i].mb, entry);
	}

	return 0;
}
