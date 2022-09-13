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

/* For gettid(). */
#define _GNU_SOURCE

#include <string.h>
#include <stdbool.h>
#include <math.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <unistd.h>
#include <time.h>

#include <rte_ip.h>
#include <rte_log.h>
#include <rte_hash.h>
#include <rte_lcore.h>
#include <rte_ethdev.h>
#include <rte_memcpy.h>
#include <rte_cycles.h>
#include <rte_malloc.h>
#include <rte_icmp.h>
#include <rte_vect.h>
#include <rte_common.h>

#include "gatekeeper_acl.h"
#include "gatekeeper_gk.h"
#include "gatekeeper_main.h"
#include "gatekeeper_lls.h"
#include "gatekeeper_config.h"
#include "gatekeeper_launch.h"
#include "gatekeeper_l2.h"
#include "gatekeeper_sol.h"
#include "gatekeeper_flow_bpf.h"

#include "bpf.h"

#define	START_PRIORITY		 (38)
/* Set @START_ALLOWANCE as the double size of a large DNS reply. */
#define	START_ALLOWANCE		 (8)

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
		G_LOG(ERR, "The present time smaller than the past time\n");
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
	size_t ether_len;
	struct rte_ether_hdr *eth_hdr;
	struct rte_ipv4_hdr *ip4_hdr;
	struct rte_ipv6_hdr *ip6_hdr;
	uint16_t pkt_len = rte_pktmbuf_data_len(pkt);

	eth_hdr = rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);
	ether_type = rte_be_to_cpu_16(pkt_in_skip_l2(pkt, eth_hdr,
		&packet->l3_hdr));
	ether_len = pkt_in_l2_hdr_len(pkt);

	switch (ether_type) {
	case RTE_ETHER_TYPE_IPV4:
		if (pkt_len < ether_len + sizeof(*ip4_hdr)) {
			packet->flow.proto = 0;
			G_LOG(NOTICE,
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
		if (pkt_len < ether_len + sizeof(*ip6_hdr)) {
			packet->flow.proto = 0;
			G_LOG(NOTICE,
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

static inline uint64_t
calc_request_expire_at(uint8_t priority, uint64_t now)
{
	uint8_t above_priority = priority + 4;

	RTE_BUILD_BUG_ON(PRIORITY_MAX >= (sizeof(uint64_t) * 8));
	if (unlikely(above_priority > PRIORITY_MAX)) {
		/* Avoid overflow of the left shift operator below. */
		above_priority = PRIORITY_MAX;
	}

	/*
	 * TCP waits for 2^i seconds between each retransmitted SYN packet,
	 * where i is greater or equal to 0. Thus, the corresponding
	 * priority p for each retransmitted packet i is:
	 *
	 * floor(log_2(2^i * 10^12)) = floor(i + log_2(10^12)) = i + 39
	 *
	 * If one sets above_priority = p + 4 and waits for the amount
	 * of time corresponding for the above_priority priority,
	 * TCP can transmit two more SYN packets:
	 *
	 * (2^(i+1)+2^(i+2)) * 10^12 <= 2 ^ above_priority =>
	 * 2^(i+1) * 10^12 + 2^(i+2) * 10^12 <= 2^(i+2) * 2^41 =>
	 * 2^(i+2) * 5 * 10^11 + 2^(i+2) * 10^12 <= 2^(i+2) * 2^41 =>
	 * 5 * 10^11 + 10^12 <= 2^41 (TRUE)
	 */

	/*
	 * The cast `(uint64_t)` is needed to force the compiler
	 * to use the 64-bit version of `<<`.
	 */
	return now + (((uint64_t)1 << above_priority) / picosec_per_cycle);
}

static inline void
initialize_flow_entry(struct flow_entry *fe, struct ip_flow *flow,
	uint32_t flow_hash_val, struct gk_fib *grantor_fib)
{
	uint64_t now = rte_rdtsc();

	/*
	 * The flow table is a critical data structure, so,
	 * whenever the size of entries grow too much,
	 * one must look for alternatives before increasing
	 * the limit below.
	 */
	RTE_BUILD_BUG_ON(sizeof(*fe) > 128);

	rte_memcpy(&fe->flow, flow, sizeof(*flow));

	fe->in_use = true;
	fe->flow_hash_val = flow_hash_val;
	fe->state = GK_REQUEST;
	fe->expire_at = calc_request_expire_at(START_PRIORITY, now);
	fe->u.request.last_packet_seen_at = now;
	fe->u.request.last_priority = START_PRIORITY;
	fe->u.request.allowance = START_ALLOWANCE - 1;
	fe->grantor_fib = grantor_fib;
}

static inline void
reinitialize_flow_entry(struct flow_entry *fe, uint64_t now)
{
	fe->state = GK_REQUEST;
	fe->expire_at = calc_request_expire_at(START_PRIORITY, now);
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
	struct rte_mbuf **req_bufs, uint16_t *num_reqs,
	struct sol_config *sol_conf)
{
	int ret;
	uint64_t now = rte_rdtsc();
	uint8_t priority = priority_from_delta_time(now,
			fe->u.request.last_packet_seen_at);
	struct ether_cache *eth_cache;
	struct grantor_entry *grantor;

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
		fe->expire_at = calc_request_expire_at(priority, now);
	}

	/*
	 * Adjust @priority for the DSCP field.
	 * DSCP 0 for legacy packets; 1 for granted packets; 
	 * 2 for capability renew; 3-63 for requests.
	 */
	priority += PRIORITY_REQ_MIN;
	if (unlikely(priority > PRIORITY_MAX))
		priority = PRIORITY_MAX;

	/* The assigned priority is @priority. */

	grantor = choose_grantor_per_flow(fe);

	/* Encapsulate the packet as a request. */
	ret = encapsulate(packet->pkt, priority,
		&sol_conf->net->back, &grantor->gt_addr);
	if (ret < 0)
		return ret;

	eth_cache = grantor->eth_cache;
	RTE_VERIFY(eth_cache != NULL);
	/* If needed, packet header space was adjusted by encapsulate(). */
	if (pkt_copy_cached_eth_header(packet->pkt, eth_cache,
			sol_conf->net->back.l2_len_out))
		return -1;

	req_bufs[*num_reqs] = packet->pkt;
	set_prio(req_bufs[*num_reqs], priority);
	(*num_reqs)++;

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
	struct rte_mbuf **req_bufs, uint16_t *num_reqs,
	struct sol_config *sol_conf, struct gk_measurement_metrics *stats)
{
	int ret;
	bool renew_cap;
	uint8_t priority = PRIORITY_GRANTED;
	uint64_t now = rte_rdtsc();
	struct rte_mbuf *pkt = packet->pkt;
	struct ether_cache *eth_cache;
	struct grantor_entry *grantor;
	uint32_t pkt_len;

	if (now >= fe->expire_at) {
		reinitialize_flow_entry(fe, now);
		return gk_process_request(fe, packet, req_bufs,
			num_reqs, sol_conf);
	}

	if (now >= fe->u.granted.budget_renew_at) {
		fe->u.granted.budget_renew_at = now + cycles_per_sec;
		fe->u.granted.budget_byte =
			(uint64_t)fe->u.granted.tx_rate_kib_cycle * 1024;
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

	grantor = choose_grantor_per_flow(fe);

	/*
	 * Encapsulate packet as a granted packet,
	 * mark it as a capability renewal request if @renew_cap is true,
	 * enter destination according to @fe->grantor_fib.
	 */
	ret = encapsulate(packet->pkt, priority,
		&sol_conf->net->back, &grantor->gt_addr);
	if (ret < 0)
		return ret;

	eth_cache = grantor->eth_cache;
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
	struct rte_mbuf **req_bufs, uint16_t *num_reqs,
	struct sol_config *sol_conf, struct gk_measurement_metrics *stats)
{
	uint64_t now = rte_rdtsc();

	if (unlikely(now >= fe->expire_at)) {
		reinitialize_flow_entry(fe, now);
		return gk_process_request(fe, packet, req_bufs,
			num_reqs, sol_conf);
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
	struct rte_mbuf **req_bufs, uint16_t *num_reqs,
	struct gk_config *gk_conf, struct gk_measurement_metrics *stats)
{
	uint64_t bpf_ret;
	int program_index, rc;
	uint64_t now = rte_rdtsc();

	if (unlikely(now >= fe->expire_at))
		goto expired;

	program_index = fe->program_index;
	rc = gk_bpf_decide_pkt(gk_conf, program_index, fe, packet, now,
		&bpf_ret);
	if (unlikely(rc != 0)) {
		G_LOG(WARNING,
			"The BPF program at index %u failed to run its function pkt\n",
			program_index);
		goto expired;
	}

	switch (bpf_ret) {
	case GK_BPF_PKT_RET_FORWARD: {
		struct ether_cache *eth_cache =
			choose_grantor_per_flow(fe)->eth_cache;
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
		G_LOG(WARNING,
			"The function pkt of the BPF program at index %u returned GK_BPF_PKT_RET_ERROR\n",
			program_index);
		return -1;
	default:
		G_LOG(WARNING,
			"The function pkt of the BPF program at index %u returned an invalid return: %" PRIu64 "\n",
			program_index, bpf_ret);
		return -1;
	}

	rte_panic("Unexpected condition at %s()", __func__);

expired:
	reinitialize_flow_entry(fe, now);
	return gk_process_request(fe, packet, req_bufs, num_reqs,
		gk_conf->sol_conf);
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

static void
print_flow_state(struct flow_entry *fe)
{
	int ret;
	char grantor_ip[RTE_MAX(MAX_INET_ADDRSTRLEN, 128)];
	char state_msg[1024];
	const char *s_in_use = likely(fe->in_use) ? "" : "NOT in use ";

	if (unlikely(fe->grantor_fib == NULL)) {
		ret = snprintf(grantor_ip, sizeof(grantor_ip),
			"NULL FIB entry");
		goto fib_error;
	}

	if (unlikely(fe->grantor_fib->action != GK_FWD_GRANTOR)) {
		ret = snprintf(grantor_ip, sizeof(grantor_ip),
			"INVALID FIB entry [FIB action: %hhu]",
			fe->grantor_fib->action);
		goto fib_error;
	}

	ret = convert_ip_to_str(&choose_grantor_per_flow(fe)->gt_addr,
		grantor_ip, sizeof(grantor_ip));
	if (ret < 0) {
		ret = snprintf(grantor_ip, sizeof(grantor_ip),
			"GRANTOR FIB entry with INVALID IP address");
		goto fib_error;
	}

	goto dump;

fib_error:
	RTE_VERIFY(ret > 0 && ret < (int)sizeof(grantor_ip));
dump:
	switch (fe->state) {
	case GK_REQUEST:
		ret = snprintf(state_msg, sizeof(state_msg),
			"%s[state: GK_REQUEST (%hhu), flow_hash_value: 0x%x, expire_at: 0x%"PRIx64", last_packet_seen_at: 0x%"PRIx64", last_priority: %hhu, allowance: %hhu, grantor_ip: %s]",
			s_in_use, fe->state, fe->flow_hash_val, fe->expire_at,
			fe->u.request.last_packet_seen_at,
			fe->u.request.last_priority, fe->u.request.allowance,
			grantor_ip);
		break;
	case GK_GRANTED:
		ret = snprintf(state_msg, sizeof(state_msg),
			"%s[state: GK_GRANTED (%hhu), flow_hash_value: 0x%x, expire_at: 0x%"PRIx64", budget_renew_at: 0x%"PRIx64", tx_rate_kib_cycle: %u, budget_byte: %"PRIu64", send_next_renewal_at: 0x%"PRIx64", renewal_step_cycle: 0x%"PRIx64", grantor_ip: %s]",
			s_in_use, fe->state, fe->flow_hash_val, fe->expire_at,
			fe->u.granted.budget_renew_at,
			fe->u.granted.tx_rate_kib_cycle,
			fe->u.granted.budget_byte,
			fe->u.granted.send_next_renewal_at,
			fe->u.granted.renewal_step_cycle,
			grantor_ip);
		break;
	case GK_DECLINED:
		ret = snprintf(state_msg, sizeof(state_msg),
			"%s[state: GK_DECLINED (%hhu), flow_hash_value: 0x%x, expire_at: 0x%"PRIx64", grantor_ip: %s]",
			s_in_use, fe->state, fe->flow_hash_val, fe->expire_at,
			grantor_ip);
		break;
	case GK_BPF: {
		uint64_t *c = fe->u.bpf.cookie.mem;

		RTE_BUILD_BUG_ON(RTE_DIM(fe->u.bpf.cookie.mem) != 8);

		ret = snprintf(state_msg, sizeof(state_msg),
			"%s[state: GK_BPF (%hhu), flow_hash_value: 0x%x, expire_at: 0x%"PRIx64", program_index=%u, cookie=%016"PRIx64", %016"PRIx64", %016"PRIx64", %016"PRIx64", %016"PRIx64", %016"PRIx64", %016"PRIx64", %016"PRIx64", grantor_ip: %s]",
			s_in_use, fe->state, fe->flow_hash_val, fe->expire_at,
			fe->program_index,
			rte_cpu_to_be_64(c[0]), rte_cpu_to_be_64(c[1]),
			rte_cpu_to_be_64(c[2]), rte_cpu_to_be_64(c[3]),
			rte_cpu_to_be_64(c[4]), rte_cpu_to_be_64(c[5]),
			rte_cpu_to_be_64(c[6]), rte_cpu_to_be_64(c[7]),
			grantor_ip);
		break;
	}
	default:
		ret = snprintf(state_msg, sizeof(state_msg),
			"%s[state: UNKNOWN (%hhu), flow_hash_value: 0x%x, expire_at: 0x%"PRIx64", grantor_ip: %s]",
			s_in_use, fe->state, fe->flow_hash_val, fe->expire_at,
			grantor_ip);
		break;
	}

	RTE_VERIFY(ret > 0 && ret < (int)sizeof(state_msg));
	print_flow_err_msg(&fe->flow, state_msg);
}

static inline void
reset_fe(struct gk_instance *instance, struct flow_entry *fe)
{
	memset(fe, 0, sizeof(*fe));
	if (instance->num_scan_del > 0)
		instance->num_scan_del--;
}

static void gk_del_flow_entry_with_key(struct gk_instance *instance,
	const struct ip_flow *flow_key, uint32_t entry_idx);

static void
found_corruption_in_flow_table(struct gk_instance *instance)
{
	if (likely(instance->scan_waiting_eoc)) {
		/*
		 * This condition is likely because once corruption is found,
		 * a number of other corruptions are often found.
		 */
		return;
	}
	instance->scan_waiting_eoc = true;
	instance->scan_end_cycle_idx = instance->scan_cur_flow_idx;
}

static inline bool
is_flow_valid(const struct ip_flow *flow)
{
	/*
	 * If @flow does not satify the following constraints,
	 * rss_ip_flow_hf() cannot work.
	 */
	return flow->proto == RTE_ETHER_TYPE_IPV4 ||
		flow->proto == RTE_ETHER_TYPE_IPV6;
}

/*
 * This function is way more complex than necessary because
 * it heals the flow table in case the table is corrupted.
 * Thus, GK blocks can recover and keep going. Moreover, this function logs
 * lots of information to hopefully enable one to identify the source of
 * corruption.
 *
 * While editing the code of this function, preserve the following constraints:
 *
 * 1. There should be NO significant performance impact when
 *    the flow table is not corrupted;
 *
 * 2. The code should be robust enough to handle any recoverable corruption;
 *
 * 3. The code should minimally rely on the internals of
 *    the hash table library used.
 *
 * Non-exhaustive list of possible corruptions that this function fixes:
 *
 * 1. Two flow keys pointing to the same flow entry.
 *
 * 2. A flow entry without a flow key pointing to it.
 *
 * 3. Two flow entries with the same flow key.
 *
 * 4. A flow entry with a wrong hash value.
 */
static void
gk_del_flow_entry_at_pos(struct gk_instance *instance, uint32_t entry_idx)
{
	struct rte_hash *h = instance->ip_flow_hash_table;
	struct flow_entry *fe = &instance->ip_flow_entry_table[entry_idx];
	struct flow_entry *fe2;
	int ret, ret2;
	char err_msg[512];
	hash_sig_t recomp_hash;

	/*
	 * Do NOT check if @fe->in_use is true to enable the code below
	 * to identify any corruption; including flow entries that are invalid
	 * only because @fe->in_use is false.
	 */

	if (unlikely(!is_flow_valid(&fe->flow))) {
		ret2 = snprintf(err_msg, sizeof(err_msg),
			"%s(): flow key is invalid at position %u; logging and removing flow entry...",
			__func__, entry_idx);
		RTE_VERIFY(ret2 > 0 && ret2 < (int)sizeof(err_msg));
		print_flow_err_msg(&fe->flow, err_msg);
		print_flow_state(fe);
		goto del;
	}

	ret = rte_hash_del_key_with_hash(h, &fe->flow, fe->flow_hash_val);
	if (likely(ret >= 0)) {
		if (likely(entry_idx == (typeof(entry_idx))ret)) {
			/* This is the ONLY normal outcome of this function. */
			reset_fe(instance, fe);
			return;
		}

		ret2 = snprintf(err_msg, sizeof(err_msg),
			"%s(): there are two flow entries for the same flow; the main entry is at position %i and the duplicate at position %u; logging and removing both entries...",
			__func__, ret, entry_idx);
		RTE_VERIFY(ret2 > 0 && ret2 < (int)sizeof(err_msg));
		print_flow_err_msg(&fe->flow, err_msg);
		fe2 = &instance->ip_flow_entry_table[ret];
		print_flow_state(fe2);
		reset_fe(instance, fe2);
		print_flow_state(fe);
		goto del;
	}

	if (unlikely(ret != -ENOENT)) {
		ret2 = snprintf(err_msg, sizeof(err_msg),
			"%s(): failed to delete a flow (errno=%i): %s; logging flow and dropping it...",
			__func__, -ret, strerror(-ret));
		RTE_VERIFY(ret2 > 0 && ret2 < (int)sizeof(err_msg));
		print_flow_err_msg(&fe->flow, err_msg);
		print_flow_state(fe);
		goto del;
	}

	RTE_VERIFY(ret == -ENOENT);

	/*
	 * The flow entry cannot be found in the flow table.
	 */

	recomp_hash = rte_hash_hash(h, &fe->flow);

	if (fe->flow_hash_val == recomp_hash) {
		ret2 = snprintf(err_msg, sizeof(err_msg),
			"%s(): flow was not indexed; logging and dropping flow...",
			__func__);
		RTE_VERIFY(ret2 > 0 && ret2 < (int)sizeof(err_msg));
		print_flow_err_msg(&fe->flow, err_msg);
		print_flow_state(fe);
		goto del;
	}

	ret2 = snprintf(err_msg, sizeof(err_msg),
		"%s(): flow had wrong hash value (0x%x); fixed hash value to 0x%x; correcting, logging, and dropping flow entry...",
		__func__, fe->flow_hash_val, recomp_hash);
	RTE_VERIFY(ret2 > 0 && ret2 < (int)sizeof(err_msg));
	print_flow_err_msg(&fe->flow, err_msg);
	fe->flow_hash_val = recomp_hash;
	print_flow_state(fe);

	ret = rte_hash_lookup_with_hash(h, &fe->flow, fe->flow_hash_val);
	if (ret < 0) {
		ret2 = snprintf(err_msg, sizeof(err_msg),
			"%s(): failed to look flow up even after fixing its hash value errno=%i: %s",
			__func__, -ret, strerror(-ret));
		RTE_VERIFY(ret2 > 0 && ret2 < (int)sizeof(err_msg));
		print_flow_err_msg(&fe->flow, err_msg);
		/*
		 * Although the hash was wrong, the entry was not indexed.
		 * So it is safe to release it.
		 */
		goto del;
	}

	if (entry_idx != (typeof(entry_idx))ret) {
		ret2 = snprintf(err_msg, sizeof(err_msg),
			"%s(): there is a duplicate flow entry at %i for entry at %u; logging and releasing duplicate entry...",
			__func__, ret, entry_idx);
		RTE_VERIFY(ret2 > 0 && ret2 < (int)sizeof(err_msg));
		print_flow_err_msg(&fe->flow, err_msg);
		fe2 = &instance->ip_flow_entry_table[ret];
		print_flow_state(fe2);
		gk_del_flow_entry_with_key(instance, &fe->flow, ret);
		goto del;
	}

	ret = rte_hash_del_key_with_hash(h, &fe->flow, fe->flow_hash_val);
	if (unlikely(ret < 0)) {
		ret2 = snprintf(err_msg, sizeof(err_msg),
			"%s(): failed to remove flow entry even after fixing its hash value errno=%i: %s",
			__func__, -ret, strerror(-ret));
		RTE_VERIFY(ret2 > 0 && ret2 < (int)sizeof(err_msg));
		print_flow_err_msg(&fe->flow, err_msg);
	} else if (unlikely(entry_idx != (typeof(entry_idx))ret)) {
		ret2 = snprintf(err_msg, sizeof(err_msg),
			"%s(): there is bug in the hash table library of DPDK: a lookup for a flow returned position %u, but, while removing the flow, rte_hash_del_key_with_hash() returned position %i; logging this second flow entry and releasing both entries...",
			__func__, entry_idx, ret);
		RTE_VERIFY(ret2 > 0 && ret2 < (int)sizeof(err_msg));
		print_flow_err_msg(&fe->flow, err_msg);
		fe2 = &instance->ip_flow_entry_table[ret];
		print_flow_state(fe2);
		reset_fe(instance, fe2);
	}

del:
	reset_fe(instance, fe);
	found_corruption_in_flow_table(instance);
}

/*
 * ATTENTION
 * This function should only be called when a lookup of @flow_key has
 * returned @entry_idx. If this is not the case, you may want to call
 * gk_del_flow_entry_at_pos() instead.
 */
static void
gk_del_flow_entry_with_key(struct gk_instance *instance,
	const struct ip_flow *flow_key, uint32_t entry_idx)
{
	struct flow_entry *fe = &instance->ip_flow_entry_table[entry_idx];
	struct ip_flow copy_flow_key;
	/*
	 * Use @ret2 instead of @ret to pair this function with its sister
	 * function gk_del_flow_entry_at_pos().
	 */
	int ret, ret2;
	char err_msg[256];

	if (unlikely(!is_flow_valid(flow_key))) {
		ret = rte_hash_free_key_with_position(
			instance->ip_flow_hash_table, entry_idx);
		ret2 = snprintf(err_msg, sizeof(err_msg),
			"%s(): flow_key is invalid at position %u. rte_hash_free_key_with_position() returned %i (i.e. %s). Logging and removing flow entry...",
			__func__, entry_idx, ret, rte_strerror(-ret));
		RTE_VERIFY(ret2 > 0 && ret2 < (int)sizeof(err_msg));
		print_flow_err_msg(&fe->flow, err_msg);
		print_flow_state(fe);
		found_corruption_in_flow_table(instance);
		return gk_del_flow_entry_at_pos(instance, entry_idx);
	}

	if (likely(flow_key_eq(flow_key, &fe->flow)))
		return gk_del_flow_entry_at_pos(instance, entry_idx);

	found_corruption_in_flow_table(instance);

	ret2 = snprintf(err_msg, sizeof(err_msg),
		"%s(): the flow entry does not correspond to the flow key at postion %u; logging entry and releasing both flow keys...",
		__func__, entry_idx);
	RTE_VERIFY(ret2 > 0 && ret2 < (int)sizeof(err_msg));
	print_flow_err_msg(flow_key, err_msg);
	print_flow_state(fe);

	/*
	 * Back up the value of @*flow_key because if it is contained in @fe,
	 * the following call of gk_del_flow_entry_at_pos() below may modify it.
	 */
	copy_flow_key = *flow_key;
	/* Remove the wrong entry. */
	gk_del_flow_entry_at_pos(instance, entry_idx);

	/* Remove the key that originated this call. */
	fe->flow = copy_flow_key;
	fe->flow_hash_val = rte_hash_hash(instance->ip_flow_hash_table,
		&fe->flow);
	gk_del_flow_entry_at_pos(instance, entry_idx);
}

static int
setup_gk_instance(unsigned int lcore_id, struct gk_config *gk_conf)
{
	int  ret;
	char ht_name[64];
	unsigned int block_idx = get_block_idx(gk_conf, lcore_id);
	unsigned int socket_id = rte_lcore_to_socket_id(lcore_id);

	struct gk_instance *instance = &gk_conf->instances[block_idx];
	struct rte_hash_parameters ip_flow_hash_params = {
		.entries = gk_conf->flow_ht_size < HASH_TBL_MIN_SIZE
			? HASH_TBL_MIN_SIZE
			: gk_conf->flow_ht_size,
		.key_len = sizeof(struct ip_flow),
		.hash_func = rss_ip_flow_hf,
		.hash_func_init_val = 0,
		.socket_id = socket_id,
	};

	ret = snprintf(ht_name, sizeof(ht_name), "ip_flow_hash_%u", block_idx);
	RTE_VERIFY(ret > 0 && ret < (int)sizeof(ht_name));

	/* Setup the flow hash table for GK block @block_idx. */
	ip_flow_hash_params.name = ht_name;
	instance->ip_flow_hash_table = rte_hash_create(&ip_flow_hash_params);
	if (instance->ip_flow_hash_table == NULL) {
		G_LOG(ERR,
			"The GK block cannot create hash table at lcore %u\n",
			lcore_id);

		ret = -1;
		goto out;
	}
	/* Set a new hash compare function other than the default one. */
	rte_hash_set_cmp_func(instance->ip_flow_hash_table, ip_flow_cmp_eq);

	/* Setup the flow entry table for GK block @block_idx. */
	instance->ip_flow_entry_table = rte_calloc_socket(
		NULL, gk_conf->flow_ht_size, sizeof(struct flow_entry), 0, socket_id);
	if (instance->ip_flow_entry_table == NULL) {
		G_LOG(ERR,
			"The GK block can't create flow entry table at lcore %u\n",
			lcore_id);

		ret = -1;
		goto flow_hash;
	}

	ret = init_mailbox("gk", gk_conf->mailbox_max_entries_exp,
		sizeof(struct gk_cmd_entry), gk_conf->mailbox_mem_cache_size,
		lcore_id, &instance->mb);
	if (ret < 0)
		goto flow_entry;

	tb_ratelimit_state_init(&instance->front_icmp_rs,
		gk_conf->front_icmp_msgs_per_sec,
		gk_conf->front_icmp_msgs_burst);
	tb_ratelimit_state_init(&instance->back_icmp_rs,
		gk_conf->back_icmp_msgs_per_sec,
		gk_conf->back_icmp_msgs_burst);

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

/*
 * If the table is full at a given batch, there's no reason to risk trying
 * another flow in the current batch because the table only has a chance
 * to free entries in between batches.
 */
static int
gk_hash_add_flow_entry(struct gk_instance *instance,
	struct ip_flow *flow, uint32_t rss_hash_val, struct gk_config *gk_conf)
{
	int ret;

	if (instance->num_scan_del > 0)
		return -ENOSPC;

	ret = rte_hash_add_key_with_hash(
		instance->ip_flow_hash_table, flow, rss_hash_val);
	if (ret == -ENOSPC)
		instance->num_scan_del = gk_conf->scan_del_thresh;

	return ret;
}

/*
 * If the test can be done only on @flow, do not access @fe to minimize
 * pressure on the processor cache of the lcore.
 */
typedef bool (*test_flow_entry_t)(void *arg, const struct ip_flow *flow,
	struct flow_entry *fe);

static void
flush_flow_table(struct gk_instance *instance, test_flow_entry_t test,
	void *arg, const char *context)
{
	uint64_t num_flushed_flows = 0;
	uint32_t next = 0;
	int32_t index;
	const void *key;
	void *data;

	index = rte_hash_iterate(instance->ip_flow_hash_table,
		&key, &data, &next);
	while (index >= 0) {
		struct flow_entry *fe =
			&instance->ip_flow_entry_table[index];

		if (test(arg, key, fe)) {
			gk_del_flow_entry_with_key(instance, key, index);
			num_flushed_flows++;
		}

		index = rte_hash_iterate(instance->ip_flow_hash_table,
			&key, &data, &next);
	}

	G_LOG(NOTICE, "Flushed %" PRIu64 " flows of the flow table due to %s\n",
		num_flushed_flows, context);
}

struct flush_net_prefixes {
	uint16_t proto;
	struct ip_prefix *src;
	struct ip_prefix *dst;
	struct in_addr ip4_src_mask;
	struct in_addr ip4_dst_mask;
	struct in6_addr ip6_src_mask;
	struct in6_addr ip6_dst_mask;
};

static bool
test_net_prefixes(void *arg, const struct ip_flow *flow,
	__attribute__((unused)) struct flow_entry *fe)
{
	struct flush_net_prefixes *info = arg;
	bool matched = true;

	if (info->proto != flow->proto)
		return false;

	if (info->proto == RTE_ETHER_TYPE_IPV4) {
		if (info->src->len != 0) {
			matched = ip4_same_subnet(
				info->src->addr.ip.v4.s_addr,
				flow->f.v4.src.s_addr,
				info->ip4_src_mask.s_addr);
		}

		if (matched && info->dst->len != 0) {
			matched = ip4_same_subnet(
				info->dst->addr.ip.v4.s_addr,
				flow->f.v4.dst.s_addr,
				info->ip4_dst_mask.s_addr);
		}

		return matched;
	}

	if (info->src->len != 0) {
		matched = ip6_same_subnet(&info->src->addr.ip.v6,
			&flow->f.v6.src, &info->ip6_src_mask);
	}

	if (matched && info->dst->len != 0) {
		matched = ip6_same_subnet(&info->dst->addr.ip.v6,
			&flow->f.v6.dst, &info->ip6_dst_mask);
	}

	return matched;
}

static void
flush_net_prefixes(struct ip_prefix *src,
	struct ip_prefix *dst, struct gk_instance *instance)
{
	struct flush_net_prefixes arg;

	RTE_VERIFY(src->addr.proto == dst->addr.proto);
	arg.proto = src->addr.proto;
	arg.src = src;
	arg.dst = dst;

	if (arg.proto == RTE_ETHER_TYPE_IPV4) {
		ip4_prefix_mask(src->len, &arg.ip4_src_mask);
		ip4_prefix_mask(dst->len, &arg.ip4_dst_mask);

		memset(&arg.ip6_src_mask, 0, sizeof(arg.ip6_src_mask));
		memset(&arg.ip6_dst_mask, 0, sizeof(arg.ip6_dst_mask));
	} else if (likely(arg.proto == RTE_ETHER_TYPE_IPV6)) {
		memset(&arg.ip4_src_mask, 0, sizeof(arg.ip4_src_mask));
		memset(&arg.ip4_dst_mask, 0, sizeof(arg.ip4_dst_mask));

		ip6_prefix_mask(src->len, &arg.ip6_src_mask);
		ip6_prefix_mask(dst->len, &arg.ip6_dst_mask);
	} else
		rte_panic("Unexpected protocol: %i\n", src->addr.proto);

	flush_flow_table(instance, test_net_prefixes, &arg, __func__);
}

static void
log_flow_state(struct gk_log_flow *log, struct gk_instance *instance)
{
	struct flow_entry *fe;
	int ret = rte_hash_lookup_with_hash(instance->ip_flow_hash_table,
		&log->flow, log->flow_hash_val);
	if (ret < 0) {
		char err_msg[128];
		ret = snprintf(err_msg, sizeof(err_msg),
			"%s(): flow does not exist\n", __func__);
		RTE_VERIFY(ret > 0 && ret < (int)sizeof(err_msg));
		print_flow_err_msg(&log->flow, err_msg);
		return;
	}

	fe = &instance->ip_flow_entry_table[ret];
	print_flow_state(fe);
}

static bool
test_fib(void *arg, __attribute__((unused)) const struct ip_flow *flow,
	struct flow_entry *fe)
{
	return fe->grantor_fib == arg;
}

static void
gk_synchronize(struct gk_synch_request *req, struct gk_instance *instance)
{
	if (req->update_only)
		goto done;

	switch (req->fib->action) {
	case GK_FWD_GRANTOR:
		/* Flush the grantor @fib in the flow table. */
		flush_flow_table(instance, test_fib, req->fib, __func__);
		break;

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
		rte_panic("%s() at lcore %u: invalid FIB action (%u)\n",
			__func__, rte_lcore_id(), req->fib->action);
		break;
	}

done:
	rte_atomic32_inc(req->done_counter);
}

static bool
test_bpf(void *arg, __attribute__((unused)) const struct ip_flow *flow,
	struct flow_entry *fe)
{
	return fe->state == GK_BPF && fe->program_index == (uintptr_t)arg;
}

static void
process_gk_cmd(struct gk_cmd_entry *entry, struct gk_add_policy **policies,
	int *num_policies, struct gk_instance *instance)
{
	switch (entry->op) {
	case GK_ADD_POLICY_DECISION:
		policies[(*num_policies)++] = &entry->u.ggu;
		break;

	case GK_SYNCH_WITH_LPM:
		gk_synchronize(&entry->u.synch, instance);
		break;

	case GK_FLUSH_FLOW_TABLE:
		flush_net_prefixes(&entry->u.flush.src,
			&entry->u.flush.dst, instance);
		break;

	case GK_LOG_FLOW_STATE:
		log_flow_state(&entry->u.log, instance);
		break;

	case GK_FLUSH_BPF:
		/*
		 * Release the message sender now because we already have
		 * a local copy of entry->u.flush_bpf.program_index.
		 */
		rte_atomic32_inc(entry->u.flush_bpf.done_counter);

		flush_flow_table(instance, test_bpf,
			(void *)(uintptr_t)entry->u.flush_bpf.program_index,
			"GK_FLUSH_BPF");
		break;

	default:
		G_LOG(ERR, "Unknown command operation %u\n", entry->op);
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
			G_LOG(ERR,
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
			G_LOG(ERR,
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
		fill_vlan_hdr(icmp_eth, iface->ipv4_vlan_tag_be,
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

	pkt->l2_len = iface->l2_len_out;
	pkt->l3_len = sizeof(struct rte_ipv4_hdr);
	set_ipv4_checksum(iface, pkt, icmp_ipv4);

	icmph = (struct rte_icmp_hdr *)&icmp_ipv4[1];
	icmph->icmp_type = ICMP_TIME_EXCEEDED;
	icmph->icmp_code = ICMP_EXC_TTL;
	icmph->icmp_cksum = 0;
	icmph->icmp_ident = 0;
	icmph->icmp_seq_nb = 0;
	icmph->icmp_cksum = icmp_cksum(icmph,
		pkt->pkt_len - (pkt->l2_len + pkt->l3_len));

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
			G_LOG(ERR,
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
			G_LOG(ERR,
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
		fill_vlan_hdr(icmp_eth, iface->ipv6_vlan_tag_be,
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
		G_LOG(WARNING,
			"Unexpected condition at %s: unknown flow type %hu\n",
			__func__, packet->flow.proto);
		cb_f(packet->pkt, instance);
		return -EINVAL;
	}

	return 0;
}

/*
 * This function is only to be called on flows that
 * are not backed by a flow entry.
 */
static void
send_request_to_grantor(struct ipacket *packet, uint32_t flow_hash_val,
		struct gk_fib *fib, struct rte_mbuf **req_bufs,
		uint16_t *num_reqs, struct gk_instance *instance,
		struct gk_config *gk_conf)
{
	int ret;
	struct flow_entry temp_fe;

	initialize_flow_entry(&temp_fe, &packet->flow, flow_hash_val, fib);

	ret = gk_process_request(&temp_fe, packet, req_bufs,
		num_reqs, gk_conf->sol_conf);
	if (ret < 0)
		drop_packet_front(packet->pkt, instance);
}

static void
lookup_fib_bulk(struct gk_lpm *ltbl, struct ip_flow **flows, int num_flows,
	struct gk_fib *fibs[])
{
	int i;
	/* The batch size for IPv4 LPM table lookup. */
	const uint8_t FWDSTEP = 4;
	const uint32_t default_nh = -1;
	int k = RTE_ALIGN_FLOOR(num_flows, FWDSTEP);

	RTE_BUILD_BUG_ON(sizeof(*fibs[0]) > RTE_CACHE_LINE_SIZE);

	if (num_flows == 0)
		return;

	for (i = 0; i < k; i += FWDSTEP) {
		int j;
		const __m128i bswap_mask = _mm_set_epi8(12, 13, 14, 15, 8, 9, 10, 11,
			4, 5, 6, 7, 0, 1, 2, 3);
		__m128i dip = _mm_set_epi32(flows[i + 3]->f.v4.dst.s_addr,
			flows[i + 2]->f.v4.dst.s_addr,
			flows[i + 1]->f.v4.dst.s_addr,
			flows[i]->f.v4.dst.s_addr);
		rte_xmm_t dst;

		/* Byte swap 4 IPV4 addresses. */
		dip = _mm_shuffle_epi8(dip, bswap_mask);

		rte_lpm_lookupx4(ltbl->lpm, dip, dst.u32, default_nh);

		for (j = 0; j < FWDSTEP; j++) {
			if (dst.u32[j] != default_nh) {
				fibs[i + j] = &ltbl->fib_tbl[dst.u32[j]];
				rte_prefetch0(fibs[i + j]);
			} else
				fibs[i + j] = NULL;
		}
	}

	RTE_VERIFY(i == k);

	for (; i < num_flows; i++) {
		int fib_id = lpm_lookup_ipv4(ltbl->lpm,
			flows[i]->f.v4.dst.s_addr);
		if (fib_id >= 0) {
			fibs[i] = &ltbl->fib_tbl[fib_id];
			rte_prefetch0(fibs[i]);
		} else
			fibs[i] = NULL;
	}
}

static void
lookup_fib6_bulk(struct gk_lpm *ltbl, struct ip_flow **flows,
	int num_flows, struct gk_fib *fibs[])
{
	int i;
	uint8_t dst_ip[num_flows][RTE_LPM6_IPV6_ADDR_SIZE];
	int32_t hop[num_flows];

	RTE_BUILD_BUG_ON(sizeof(*fibs[0]) > RTE_CACHE_LINE_SIZE);

	if (num_flows == 0)
		return;

	for (i = 0; i < num_flows; i++) {
		memcpy(&dst_ip[i][0], flows[i]->f.v6.dst.s6_addr,
			sizeof(dst_ip[i]));
	}

	rte_lpm6_lookup_bulk_func(ltbl->lpm6, dst_ip, hop, num_flows);

	for (i = 0; i < num_flows; i++) {
		if (hop[i] != -1) {
			fibs[i] = &ltbl->fib_tbl6[hop[i]];

			rte_prefetch0(fibs[i]);
		} else
			fibs[i] = NULL;
	}
}

static struct flow_entry *
lookup_fe_from_lpm(struct ipacket *packet, uint32_t ip_flow_hash_val,
		struct gk_fib *fib, int32_t *fe_index,
		uint16_t *num_tx, struct rte_mbuf **tx_bufs,
		struct acl_search *acl4, struct acl_search *acl6,
		uint16_t *num_pkts, struct rte_mbuf **icmp_bufs,
		struct rte_mbuf **req_bufs, uint16_t *num_reqs,
		struct gatekeeper_if *front, struct gatekeeper_if *back,
		struct gk_instance *instance, struct gk_config *gk_conf)
{
	struct rte_mbuf *pkt = packet->pkt;
	struct ether_cache *eth_cache;
	struct gk_measurement_metrics *stats = &instance->traffic_stats;

	if (fib == NULL || fib->action == GK_FWD_NEIGHBOR_FRONT_NET) {
		stats->tot_pkts_num_distributed++;
		stats->tot_pkts_size_distributed += rte_pktmbuf_pkt_len(pkt);
		if (packet->flow.proto == RTE_ETHER_TYPE_IPV4)
			add_pkt_acl(acl4, pkt);
		else
			add_pkt_acl(acl6, pkt);
		goto no_fe;
	}

	switch (fib->action) {
	case GK_FWD_GRANTOR: {
		struct flow_entry *fe;
		int ret = gk_hash_add_flow_entry(
			instance, &packet->flow,
			ip_flow_hash_val, gk_conf);
		if (ret == -ENOSPC) {
			/*
			 * There is no room for a new
			 * flow entry, but give this
			 * flow a chance sending a
			 * request to the grantor
			 * server.
			 */
			send_request_to_grantor(packet, ip_flow_hash_val,
				fib, req_bufs, num_reqs, instance, gk_conf);
			break;
		}
		if (ret < 0) {
			drop_packet_front(pkt, instance);
			break;
		}

		fe = &instance->ip_flow_entry_table[ret];
		initialize_flow_entry(fe, &packet->flow, ip_flow_hash_val, fib);
		*fe_index = ret;
		return fe;
	}

	case GK_FWD_GATEWAY_FRONT_NET:
		/* Gatekeeper does not intermediate neighbors. */

		/*
		 * Although this is the GK block, print_flow_err_msg() uses
		 * G_LOG, so test log level at the Gatekeeper level.
		 */
		if (unlikely(G_LOG_CHECK(DEBUG)))
			print_flow_err_msg(&packet->flow, "Dropping packet that arrived at the front interface and is destined to a front gateway");

		drop_packet_front(pkt, instance);
		break;

	case GK_FWD_GATEWAY_BACK_NET:
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
				pkt_copy_cached_eth_header(pkt, eth_cache,
					back->l2_len_out)) {
			drop_packet_front(pkt, instance);
			break;
		}

		if (update_ip_hop_count(front, packet, num_pkts, icmp_bufs,
				&instance->front_icmp_rs, instance,
				drop_packet_front) < 0)
			break;

		tx_bufs[(*num_tx)++] = pkt;
		break;

	case GK_FWD_NEIGHBOR_FRONT_NET:
		G_LOG(CRIT, "%s(): bug: GK_FWD_NEIGHBOR_FRONT_NET should have been already handled; dropping packet...\n",
			__func__);
		drop_packet_front(pkt, instance);
		break;

	case GK_FWD_NEIGHBOR_BACK_NET:
		/*
		 * The entry instructs to forward
		 * its packets to the neighbor in
		 * the back network, forward accordingly.
		 */
		if (packet->flow.proto == RTE_ETHER_TYPE_IPV4) {
			eth_cache = lookup_ether_cache(&fib->u.neigh,
				&packet->flow.f.v4.dst);
		} else {
			eth_cache = lookup_ether_cache(&fib->u.neigh,
				&packet->flow.f.v6.dst);
		}

		if (eth_cache == NULL) {
			/*
			 * Although this is the GK block, print_flow_err_msg()
			 * uses G_LOG, so test log level at the Gatekeeper
			 * level.
			 *
			 * NOTICE that the unknown back neighbor that the log
			 * entry below refers to could be the address of
			 * our back interface as well. We cannot just send
			 * the packet to the filter of the back interface
			 * because the target filter may be implemented in
			 * the hardware of the back interface.
			 */
			if (unlikely(G_LOG_CHECK(DEBUG)))
				print_flow_err_msg(&packet->flow, "Dropping packet that arrived at the front interface and is destined to an uknown back neighbor");

			drop_packet_front(pkt, instance);
			break;
		}

		if (adjust_pkt_len(pkt, back, 0) == NULL ||
				pkt_copy_cached_eth_header(pkt, eth_cache,
					back->l2_len_out)) {
			drop_packet_front(pkt, instance);
			break;
		}

		if (update_ip_hop_count(front, packet, num_pkts, icmp_bufs,
				&instance->front_icmp_rs, instance,
				drop_packet_front) < 0)
			break;

		tx_bufs[(*num_tx)++] = pkt;
		break;

	case GK_DROP:
		/* FALLTHROUGH */
	default:
		drop_packet_front(pkt, instance);
		break;
	}

no_fe:
	*fe_index = -ENOENT;
	return NULL;
}

static int
process_flow_entry(struct flow_entry *fe, int32_t fe_index,
	struct ipacket *packet, struct rte_mbuf **req_bufs, uint16_t *num_reqs,
	struct gk_config *gk_conf, struct gk_instance *instance)
{
	int ret;

	/*
	 * Some notes regarding flow rates and units:
	 *
	 * Flows in the GK_REQUEST state are bandwidth limited
	 * to an overall rate relative to the link. Therefore,
	 * the Ethernet frame overhead is counted toward the
	 * credits used by requests. The request channel rate
	 * is measured in megabits (base 10) per second to
	 * match the units used by hardware specifications.
	 *
	 * Granted flows (in state GK_GRANTED or sometimes
	 * GK_BPF) are allocated budgets that are intended
	 * to reflect the max throughput of the flow, and
	 * therefore do not include the Ethernet frame overhead.
	 * The budgets of granted flows are measured in
	 * kibibytes (base 2).
	 */
	switch (fe->state) {
	case GK_REQUEST:
		ret = gk_process_request(fe, packet,
			req_bufs, num_reqs, gk_conf->sol_conf);
		break;

	case GK_GRANTED:
		ret = gk_process_granted(fe, packet,
			req_bufs, num_reqs, gk_conf->sol_conf,
			&instance->traffic_stats);
		break;

	case GK_DECLINED:
		ret = gk_process_declined(fe, packet,
			req_bufs, num_reqs, gk_conf->sol_conf,
			&instance->traffic_stats);
		break;

	case GK_BPF:
		ret = gk_process_bpf(fe, packet,
			req_bufs, num_reqs, gk_conf,
			&instance->traffic_stats);
		break;

	default: {
		char err_msg[256];
		int ret2;

		ret = -1;

		/*
		 * The flow table is corrupted.
		 *
		 * The ideal solution would be to move the flow into
		 * the GK_REQUEST state and to process it as such.
		 * The corresponding fib entry, however, is not available
		 * to change the state, and finding the fib entry is too
		 * expensive to do here.
		 *
		 * The second best solution, done below, is to remove
		 * the flow entry.
		 */

		ret2 = snprintf(err_msg, sizeof(err_msg),
			"%s(): Unknown flow state: %i; logging and dropping flow entry...\n",
			__func__, fe->state);
		RTE_VERIFY(ret2 > 0 && ret2 < (int)sizeof(err_msg));
		print_flow_err_msg(&fe->flow, err_msg);
		print_flow_state(fe);
		gk_del_flow_entry_at_pos(instance, fe_index);
		break;
	}
	}

	return ret;
}

static inline void
prefetch_flow_entry(struct flow_entry *fe)
{
#if RTE_CACHE_LINE_SIZE == 64
	RTE_BUILD_BUG_ON(sizeof(*fe) <= RTE_CACHE_LINE_SIZE);
	RTE_BUILD_BUG_ON(sizeof(*fe) > 2 * RTE_CACHE_LINE_SIZE);
	rte_prefetch0(fe);
	rte_prefetch0(((char *)fe) + RTE_CACHE_LINE_SIZE);
#elif RTE_CACHE_LINE_SIZE == 128
	RTE_BUILD_BUG_ON(sizeof(*fe) > RTE_CACHE_LINE_SIZE);
	rte_prefetch0(fe);
#else
#error "Unsupported cache line size"
#endif
}

static void
parse_packet(struct ipacket *packet, struct rte_mbuf *pkt,
	struct rte_mbuf **arp_bufs, uint16_t *num_arp,
	bool ipv4_configured_front, bool ipv6_configured_front,
	struct ip_flow **flow_arr, uint32_t *flow_hash_val_arr,
	int *num_ip_flows, struct gatekeeper_if *front,
	struct gk_instance *instance)
{
	int ret;
	struct gk_measurement_metrics *stats = &instance->traffic_stats;

	stats->tot_pkts_size += rte_pktmbuf_pkt_len(pkt);

	ret = extract_packet_info(pkt, packet);
	if (ret < 0) {
		if (likely(packet->flow.proto == RTE_ETHER_TYPE_ARP)) {
			stats->tot_pkts_num_distributed++;
			stats->tot_pkts_size_distributed +=
				rte_pktmbuf_pkt_len(pkt);

			arp_bufs[(*num_arp)++] = pkt;
			return;
		}

		/* Drop non-IP and non-ARP packets. */
		drop_packet_front(pkt, instance);
		return;
	}

	if (unlikely((packet->flow.proto == RTE_ETHER_TYPE_IPV4 &&
			!ipv4_configured_front) ||
			(packet->flow.proto == RTE_ETHER_TYPE_IPV6 &&
			!ipv6_configured_front))) {
		drop_packet_front(pkt, instance);
		return;
	}

	flow_arr[*num_ip_flows] = &packet->flow;
	flow_hash_val_arr[*num_ip_flows] = likely(front->rss) ?
		pkt->hash.rss : rss_ip_flow_hf(&packet->flow, 0, 0);
	(*num_ip_flows)++;
}

#define PREFETCH_OFFSET (4)

/* Process the packets on the front interface. */
static void
process_pkts_front(uint16_t port_front, uint16_t rx_queue_front,
	unsigned int lcore,
	uint16_t *tx_front_num_pkts, struct rte_mbuf **tx_front_pkts,
	uint16_t *tx_back_num_pkts, struct rte_mbuf **tx_back_pkts,
	struct gk_instance *instance, struct gk_config *gk_conf)
{
	int i;
	int done_lookups;
	int ret;
	uint16_t num_rx;
	uint16_t num_arp = 0;
	uint16_t num_reqs = 0;
	uint16_t front_max_pkt_burst = gk_conf->front_max_pkt_burst;
	struct rte_mbuf *rx_bufs[front_max_pkt_burst];
	struct rte_mbuf *arp_bufs[front_max_pkt_burst];
	struct rte_mbuf *req_bufs[front_max_pkt_burst];
	DEFINE_ACL_SEARCH(acl4, front_max_pkt_burst);
	DEFINE_ACL_SEARCH(acl6, front_max_pkt_burst);
	struct gatekeeper_if *front = &gk_conf->net->front;
	struct gatekeeper_if *back = &gk_conf->net->back;
	struct gk_measurement_metrics *stats = &instance->traffic_stats;
	bool ipv4_configured_front = ipv4_if_configured(&gk_conf->net->front);
	bool ipv6_configured_front = ipv6_if_configured(&gk_conf->net->front);
	int num_ip_flows = 0;
	struct ipacket pkt_arr[front_max_pkt_burst];
	struct ip_flow *flow_arr[front_max_pkt_burst];
	uint32_t flow_hash_val_arr[front_max_pkt_burst];
	int num_lpm_lookups = 0;
	int num_lpm6_lookups = 0;
	struct ip_flow *flows[front_max_pkt_burst];
	struct ip_flow *flows6[front_max_pkt_burst];
	int32_t lpm_lookup_pos[front_max_pkt_burst];
	int32_t lpm6_lookup_pos[front_max_pkt_burst];
	int32_t pos_arr[front_max_pkt_burst];
	struct gk_fib *fibs[front_max_pkt_burst];
	struct gk_fib *fibs6[front_max_pkt_burst];
	struct flow_entry *fe_arr[front_max_pkt_burst];

	/* Load a set of packets from the front NIC. */
	num_rx = rte_eth_rx_burst(port_front, rx_queue_front, rx_bufs,
		front_max_pkt_burst);

	if (unlikely(num_rx == 0))
		return;

	stats->tot_pkts_num += num_rx;

	/*
	 * This prefetch is enough to load Ethernet header (14 bytes),
	 * optional Ethernet VLAN header (8 bytes), and either
	 * an IPv4 header without options (20 bytes), or
	 * an IPv6 header without options (40 bytes).
	 * IPv4: 14 + 8 + 20 = 42
	 * IPv6: 14 + 8 + 40 = 62
	 */
	for (i = 0; i < PREFETCH_OFFSET && i < num_rx; i++)
		rte_prefetch0(rte_pktmbuf_mtod_offset(rx_bufs[i], void *, 0));

	/* Extract packet and flow information. */
	for (i = 0; i < (num_rx - PREFETCH_OFFSET); i++) {
		rte_prefetch0(rte_pktmbuf_mtod_offset(
			rx_bufs[i + PREFETCH_OFFSET], void *, 0));

		parse_packet(&pkt_arr[num_ip_flows], rx_bufs[i], arp_bufs,
			&num_arp, ipv4_configured_front, ipv6_configured_front,
			flow_arr, flow_hash_val_arr, &num_ip_flows, front,
			instance);
	}

	/* Extract the rest packet and flow information. */
	for (; i < num_rx; i++) {
		parse_packet(&pkt_arr[num_ip_flows], rx_bufs[i], arp_bufs,
			&num_arp, ipv4_configured_front, ipv6_configured_front,
			flow_arr, flow_hash_val_arr, &num_ip_flows, front,
			instance);
	}

	done_lookups = 0;
	while (done_lookups < num_ip_flows) {
		uint32_t num_keys = num_ip_flows - done_lookups;
		if (num_keys > RTE_HASH_LOOKUP_BULK_MAX)
			num_keys = RTE_HASH_LOOKUP_BULK_MAX;

		ret = rte_hash_lookup_with_hash_bulk(
			instance->ip_flow_hash_table,
			(const void **)&flow_arr[done_lookups],
			(hash_sig_t *)&flow_hash_val_arr[done_lookups],
			num_keys, &pos_arr[done_lookups]);
		if (ret != 0)
			G_LOG(NOTICE, "Failed to find multiple keys in the hash table\n");

		done_lookups += num_keys;
	}

	for (i = 0; i < num_ip_flows; i++) {
		if (pos_arr[i] >= 0) {
			fe_arr[i] = &instance->ip_flow_entry_table[pos_arr[i]];

			prefetch_flow_entry(fe_arr[i]);
		} else {
			fe_arr[i] = NULL;
			if (flow_arr[i]->proto == RTE_ETHER_TYPE_IPV4) {
				lpm_lookup_pos[num_lpm_lookups] = i;
				flows[num_lpm_lookups] = flow_arr[i];
				num_lpm_lookups++;
			} else {
				lpm6_lookup_pos[num_lpm6_lookups] = i;
				flows6[num_lpm6_lookups] = flow_arr[i];
				num_lpm6_lookups++;
			}
		}
	}

	/* The remaining flows need LPM lookups. */
	lookup_fib_bulk(&gk_conf->lpm_tbl, flows, num_lpm_lookups, fibs);
	lookup_fib6_bulk(&gk_conf->lpm_tbl, flows6, num_lpm6_lookups, fibs6);

	for (i = 0; i < num_lpm_lookups; i++) {
		int fidx = lpm_lookup_pos[i];

		fe_arr[fidx] = lookup_fe_from_lpm(&pkt_arr[fidx],
			flow_hash_val_arr[fidx], fibs[i], &pos_arr[fidx],
			tx_back_num_pkts, tx_back_pkts, &acl4, &acl6,
			tx_front_num_pkts, tx_front_pkts, req_bufs,
			&num_reqs, front, back, instance, gk_conf);
	}

	for (i = 0; i < num_lpm6_lookups; i++) {
		int fidx = lpm6_lookup_pos[i];

		fe_arr[fidx] = lookup_fe_from_lpm(&pkt_arr[fidx],
			flow_hash_val_arr[fidx], fibs6[i], &pos_arr[fidx],
			tx_back_num_pkts, tx_back_pkts, &acl4, &acl6,
			tx_front_num_pkts, tx_front_pkts, req_bufs,
			&num_reqs, front, back, instance, gk_conf);
	}

	for (i = 0; i < num_ip_flows; i++) {
		if (fe_arr[i] == NULL)
			continue;

		ret = process_flow_entry(fe_arr[i], pos_arr[i], &pkt_arr[i],
			req_bufs, &num_reqs, gk_conf, instance);
		if (ret < 0)
			drop_packet_front(pkt_arr[i].pkt, instance);
		else if (ret == EINPROGRESS) {
			/* Request will be serviced by another lcore. */
			continue;
		} else if (likely(ret == 0))
			tx_back_pkts[(*tx_back_num_pkts)++] = pkt_arr[i].pkt;
		else
			rte_panic("Invalid return value (%d) from processing a packet in a flow with state %d",
				ret, fe_arr[i]->state);
	}

	if (num_reqs > 0) {
		uint64_t acc_size_request[num_reqs + 1];

		acc_size_request[0] = 0;
		for (i = 1; i <= num_reqs; i++) {
			acc_size_request[i] = acc_size_request[i - 1] +
				rte_pktmbuf_pkt_len(req_bufs[i - 1]);
		}

		ret = RTE_MAX(gk_solicitor_enqueue_bulk(instance->sol_inst,
			req_bufs, num_reqs), 0);
		if (ret < num_reqs) {
			for (i = ret; i < num_reqs; i++)
				drop_packet_front(req_bufs[i], instance);
		}

		stats->pkts_num_request += ret;
		stats->pkts_size_request += acc_size_request[ret];
	}

	if (num_arp > 0)
		submit_arp(arp_bufs, num_arp, &gk_conf->net->front);

	process_pkts_acl(&gk_conf->net->front,
		lcore, &acl4, RTE_ETHER_TYPE_IPV4);
	process_pkts_acl(&gk_conf->net->front,
		lcore, &acl6, RTE_ETHER_TYPE_IPV6);
}

static void
process_fib_back(struct ipacket *packet, struct gk_fib *fib, uint16_t *num_tx,
	struct rte_mbuf **tx_bufs, struct acl_search *acl4,
	struct acl_search *acl6, uint16_t *num_pkts,
	struct rte_mbuf **icmp_bufs, struct gatekeeper_if *front,
	struct gatekeeper_if *back, struct gk_instance *instance)
{
	struct rte_mbuf *pkt = packet->pkt;
	struct ether_cache *eth_cache;

	if (fib == NULL || fib->action == GK_FWD_NEIGHBOR_BACK_NET) {
		if (packet->flow.proto == RTE_ETHER_TYPE_IPV4)
			add_pkt_acl(acl4, pkt);
		else if (likely(packet->flow.proto ==
				RTE_ETHER_TYPE_IPV6))
			add_pkt_acl(acl6, pkt);
		else {
			print_flow_err_msg(&packet->flow,
				"gk: failed to get the fib entry or it is not an IP packet");
			drop_packet(pkt);
		}
		return;
	}

	switch (fib->action) {
	case GK_FWD_GATEWAY_FRONT_NET:
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
				pkt_copy_cached_eth_header(pkt, eth_cache,
					front->l2_len_out)) {
			drop_packet(pkt);
			return;
		}

		if (update_ip_hop_count(back, packet, num_pkts, icmp_bufs,
				&instance->back_icmp_rs, instance,
				drop_packet_back) < 0)
			return;

		tx_bufs[(*num_tx)++] = pkt;
		return;

	case GK_FWD_GATEWAY_BACK_NET:
		/* Gatekeeper does not intermediate neighbors. */

		/*
		 * Although this is the GK block, print_flow_err_msg() uses
		 * G_LOG, so test log level at the Gatekeeper level.
		 */
		if (unlikely(G_LOG_CHECK(DEBUG)))
			print_flow_err_msg(&packet->flow, "Dropping packet that arrived at the back interface and is destined to a back gateway");

		drop_packet(pkt);
		return;

	case GK_FWD_NEIGHBOR_FRONT_NET:
		/*
		 * The entry instructs to forward
		 * its packets to the neighbor in
		 * the front network, forward accordingly.
		 */
		if (packet->flow.proto == RTE_ETHER_TYPE_IPV4) {
			eth_cache = lookup_ether_cache(&fib->u.neigh,
				&packet->flow.f.v4.dst);
		} else {
			eth_cache = lookup_ether_cache(&fib->u.neigh,
				&packet->flow.f.v6.dst);
		}

		if (eth_cache == NULL) {
			/*
			 * Although this is the GK block, print_flow_err_msg()
			 * uses G_LOG, so test log level at the Gatekeeper
			 * level.
			 *
			 * NOTICE that the unknown front neighbor that the log
			 * entry below refers to could be the address of
			 * our front interface as well. We cannot just send
			 * the packet to the filter of the front interface
			 * because the target filter may be implemented in
			 * the hardware of the front interface.
			 */
			if (unlikely(G_LOG_CHECK(DEBUG)))
				print_flow_err_msg(&packet->flow, "Dropping packet that arrived at the back interface and is destined to an uknown front neighbor");

			drop_packet(pkt);
			return;
		}

		if (adjust_pkt_len(pkt, front, 0) == NULL ||
				pkt_copy_cached_eth_header(pkt, eth_cache,
					front->l2_len_out)) {
			drop_packet(pkt);
			return;
		}

		if (update_ip_hop_count(back, packet, num_pkts, icmp_bufs,
				&instance->back_icmp_rs, instance,
				drop_packet_back) < 0)
			return;

		tx_bufs[(*num_tx)++] = pkt;
		return;

	case GK_FWD_NEIGHBOR_BACK_NET:
		rte_panic("GK_FWD_NEIGHBOR_BACK_NET should have been already handled");
		return;

	case GK_DROP:
		drop_packet(pkt);
		return;

	default:
		/* All other actions should log a warning. */
		G_LOG(WARNING,
			"%s(): A FIB entry has the unexpected action %u\n",
			__func__, fib->action);
		drop_packet(pkt);
		return;
	}
}

/* Process the packets on the back interface. */
static void
process_pkts_back(uint16_t port_back, uint16_t rx_queue_back,
	unsigned int lcore,
	uint16_t *tx_front_num_pkts, struct rte_mbuf **tx_front_pkts,
	uint16_t *tx_back_num_pkts, struct rte_mbuf **tx_back_pkts,
	struct gk_instance *instance, struct gk_config *gk_conf)
{
	int i;
	int ret;
	uint16_t num_rx;
	uint16_t num_arp = 0;
	uint16_t back_max_pkt_burst = gk_conf->back_max_pkt_burst;
	struct rte_mbuf *rx_bufs[back_max_pkt_burst];
	struct rte_mbuf *arp_bufs[back_max_pkt_burst];
	DEFINE_ACL_SEARCH(acl4, back_max_pkt_burst);
	DEFINE_ACL_SEARCH(acl6, back_max_pkt_burst);
	struct gatekeeper_if *front = &gk_conf->net->front;
	struct gatekeeper_if *back = &gk_conf->net->back;
	bool ipv4_configured_back = ipv4_if_configured(&gk_conf->net->back);
	bool ipv6_configured_back = ipv6_if_configured(&gk_conf->net->back);
	int num_ip_flows = 0;
	struct ipacket pkt_arr[back_max_pkt_burst];
	int num_lpm_lookups = 0;
	int num_lpm6_lookups = 0;
	int lpm_lookup_pos[back_max_pkt_burst];
	int lpm6_lookup_pos[back_max_pkt_burst];
	struct ip_flow *flows[back_max_pkt_burst];
	struct ip_flow *flows6[back_max_pkt_burst];
	struct gk_fib *fibs[back_max_pkt_burst];
	struct gk_fib *fibs6[back_max_pkt_burst];

	/* Load a set of packets from the back NIC. */
	num_rx = rte_eth_rx_burst(port_back, rx_queue_back, rx_bufs,
		back_max_pkt_burst);

	if (unlikely(num_rx == 0))
		return;

	/*
	 * This prefetch is enough to load Ethernet header (14 bytes),
	 * optional Ethernet VLAN header (8 bytes), and either
	 * an IPv4 header without options (20 bytes), or
	 * an IPv6 header without options (40 bytes).
	 * IPv4: 14 + 8 + 20 = 42
	 * IPv6: 14 + 8 + 40 = 62
	 */
	for (i = 0; i < num_rx; i++)
		rte_prefetch0(rte_pktmbuf_mtod_offset(rx_bufs[i], void *, 0));

	for (i = 0; i < num_rx; i++) {
		struct ipacket *packet = &pkt_arr[num_ip_flows];
		struct rte_mbuf *pkt = rx_bufs[i];

		ret = extract_packet_info(pkt, packet);
		if (ret < 0) {
			if (likely(packet->flow.proto == RTE_ETHER_TYPE_ARP)) {
				arp_bufs[num_arp++] = pkt;
				continue;
			}

			/* Drop non-IP and non-ARP packets. */
			drop_packet(pkt);
			continue;
		}

		if (unlikely((packet->flow.proto == RTE_ETHER_TYPE_IPV4 &&
				!ipv4_configured_back) ||
				(packet->flow.proto == RTE_ETHER_TYPE_IPV6 &&
				!ipv6_configured_back))) {
			drop_packet_back(pkt, instance);
			continue;
		}

		if (packet->flow.proto == RTE_ETHER_TYPE_IPV4) {
			lpm_lookup_pos[num_lpm_lookups] = num_ip_flows;
			flows[num_lpm_lookups] = &packet->flow;
			num_lpm_lookups++;
		} else {
			lpm6_lookup_pos[num_lpm6_lookups] = num_ip_flows;
			flows6[num_lpm6_lookups] = &packet->flow;
			num_lpm6_lookups++;
		}

		num_ip_flows++;
	}

	lookup_fib_bulk(&gk_conf->lpm_tbl, flows, num_lpm_lookups, fibs);
	lookup_fib6_bulk(&gk_conf->lpm_tbl, flows6, num_lpm6_lookups, fibs6);

	for (i = 0; i < num_lpm_lookups; i++) {
		int fidx = lpm_lookup_pos[i];

		process_fib_back(&pkt_arr[fidx], fibs[i],
			tx_front_num_pkts, tx_front_pkts, &acl4, &acl6,
			tx_back_num_pkts, tx_back_pkts, front, back,
			instance);
	}

	for (i = 0; i < num_lpm6_lookups; i++) {
		int fidx = lpm6_lookup_pos[i];

		process_fib_back(&pkt_arr[fidx], fibs6[i],
			tx_front_num_pkts, tx_front_pkts, &acl4, &acl6,
			tx_back_num_pkts, tx_back_pkts, front, back,
			instance);
	}

	if (num_arp > 0)
		submit_arp(arp_bufs, num_arp, &gk_conf->net->back);

	process_pkts_acl(&gk_conf->net->back, lcore, &acl4,
		RTE_ETHER_TYPE_IPV4);
	process_pkts_acl(&gk_conf->net->back, lcore, &acl6,
		RTE_ETHER_TYPE_IPV6);
}

static void
update_flow_entry(struct flow_entry *fe, struct ggu_policy *policy)
{
	uint64_t now = rte_rdtsc();

	switch (policy->state) {
	case GK_GRANTED:
		fe->state = GK_GRANTED;
		fe->expire_at = now +
			policy->params.granted.cap_expire_sec *
			cycles_per_sec;
		fe->u.granted.tx_rate_kib_cycle =
			policy->params.granted.tx_rate_kib_sec;
		fe->u.granted.send_next_renewal_at = now +
			policy->params.granted.next_renewal_ms *
			cycles_per_ms;
		fe->u.granted.renewal_step_cycle =
			policy->params.granted.renewal_step_ms *
			cycles_per_ms;
		fe->u.granted.budget_renew_at = now + cycles_per_sec;
		fe->u.granted.budget_byte =
			(uint64_t)fe->u.granted.tx_rate_kib_cycle * 1024;
		break;

	case GK_DECLINED:
		fe->state = GK_DECLINED;
		fe->expire_at = now +
			policy->params.declined.expire_sec * cycles_per_sec;
		break;

	case GK_BPF:
		fe->state = GK_BPF;
		fe->expire_at = now +
			policy->params.bpf.expire_sec * cycles_per_sec;
		fe->program_index = policy->params.bpf.program_index;
		fe->u.bpf.cookie = policy->params.bpf.cookie;
		break;

	default:
		G_LOG(ERR, "Unknown flow state %u\n", policy->state);
		break;
	}
}

static void
update_flow_table(struct gk_fib *fib, struct ggu_policy *policy,
	struct gk_instance *instance, struct gk_config *gk_conf,
	uint32_t rss_hash_val)
{
	int ret;
	struct flow_entry *fe;

	if (fib == NULL || fib->action != GK_FWD_GRANTOR) {
		/* Drop this solicitation to add a policy decision. */
		char err_msg[128];
		ret = snprintf(err_msg, sizeof(err_msg),
			"gk: at %s initialize flow entry error",
			__func__);
		RTE_VERIFY(ret > 0 && ret < (int)sizeof(err_msg));
		print_flow_err_msg(&policy->flow, err_msg);
		return;
	}

	ret = gk_hash_add_flow_entry(instance,
		&policy->flow, rss_hash_val, gk_conf);
	if (ret < 0)
		return;

	fe = &instance->ip_flow_entry_table[ret];
	initialize_flow_entry(fe, &policy->flow, rss_hash_val, fib);
	update_flow_entry(fe, policy);
}

static void
add_ggu_policy_bulk(struct gk_add_policy **policies, int num_policies,
	struct gk_instance *instance, struct gk_config *gk_conf)
{
	int i;
	int done_lookups;
	struct ip_flow *flow_arr[num_policies];
	hash_sig_t flow_hash_val_arr[num_policies];
	int32_t pos_arr[num_policies];
	int num_lpm_lookups = 0;
	int num_lpm6_lookups = 0;
	int32_t lpm_lookup_pos[num_policies];
	int32_t lpm6_lookup_pos[num_policies];
	struct ip_flow *flows[num_policies];
	struct ip_flow *flows6[num_policies];
	struct gk_fib *fibs[num_policies];
	struct gk_fib *fibs6[num_policies];

	for (i = 0; i < num_policies; i++) {
		flow_arr[i] = &policies[i]->policy.flow;
		flow_hash_val_arr[i] = policies[i]->flow_hash_val;
	}

	done_lookups = 0;
	while (done_lookups < num_policies) {
		int ret;
		uint32_t num_keys = num_policies - done_lookups;
		if (num_keys > RTE_HASH_LOOKUP_BULK_MAX)
			num_keys = RTE_HASH_LOOKUP_BULK_MAX;

		ret = rte_hash_lookup_with_hash_bulk(
			instance->ip_flow_hash_table,
			(const void **)&flow_arr[done_lookups],
			&flow_hash_val_arr[done_lookups],
			num_keys, &pos_arr[done_lookups]);
		if (ret != 0)
			G_LOG(NOTICE, "Failed to find multiple keys in the hash table\n");

		done_lookups += num_keys;
	}

	for (i = 0; i < num_policies; i++) {
		int pos = pos_arr[i];

		if (pos >= 0) {
			struct ggu_policy *policy =
				&policies[i]->policy;
			struct flow_entry *fe =
				&instance->ip_flow_entry_table[pos];

			update_flow_entry(fe, policy);
		} else if (flow_arr[i]->proto == RTE_ETHER_TYPE_IPV4) {
			lpm_lookup_pos[num_lpm_lookups] = i;
			flows[num_lpm_lookups] = flow_arr[i];
			num_lpm_lookups++;
		} else {
			lpm6_lookup_pos[num_lpm6_lookups] = i;
			flows6[num_lpm6_lookups] = flow_arr[i];
			num_lpm6_lookups++;
		}
	}

	if (instance->num_scan_del > 0)
		return;

	/* The remaining flows need LPM lookups. */
	lookup_fib_bulk(&gk_conf->lpm_tbl, flows, num_lpm_lookups, fibs);
	lookup_fib6_bulk(&gk_conf->lpm_tbl, flows6, num_lpm6_lookups, fibs6);

	for (i = 0; i < num_lpm_lookups; i++) {
		int fidx = lpm_lookup_pos[i];

		update_flow_table(fibs[i], &policies[fidx]->policy,
			instance, gk_conf, policies[fidx]->flow_hash_val);
	}

	for (i = 0; i < num_lpm6_lookups; i++) {
		int fidx = lpm6_lookup_pos[i];

		update_flow_table(fibs6[i], &policies[fidx]->policy,
			instance, gk_conf, policies[fidx]->flow_hash_val);
	}
}

static void
process_cmds_from_mailbox(
	struct gk_instance *instance, struct gk_config *gk_conf)
{
	int i;
	int num_cmd;
	int num_policies = 0;
	unsigned int mailbox_burst_size = gk_conf->mailbox_burst_size;
	struct gk_cmd_entry *gk_cmds[mailbox_burst_size];
	struct gk_add_policy *policies[mailbox_burst_size];

	/* Load a set of commands from its mailbox ring. */
	num_cmd = mb_dequeue_burst(&instance->mb,
		(void **)gk_cmds, mailbox_burst_size);

	for (i = 0; i < num_cmd; i++)
		process_gk_cmd(gk_cmds[i], policies, &num_policies, instance);

	if (num_policies > 0)
		add_ggu_policy_bulk(policies, num_policies, instance, gk_conf);

	mb_free_entry_bulk(&instance->mb, (void * const *)gk_cmds, num_cmd);
}

static bool
test_invalid_flow(__attribute__((unused)) void *arg,
	const struct ip_flow *flow, struct flow_entry *fe)
{
	if (unlikely(!is_flow_valid(flow) || !is_flow_valid(&fe->flow) ||
			!flow_key_eq(flow, &fe->flow) ||
			!fe->in_use || fe->grantor_fib == NULL ||
			fe->grantor_fib->action != GK_FWD_GRANTOR
			))
		return true;

	switch (fe->state) {
	case GK_REQUEST:
	case GK_GRANTED:
	case GK_DECLINED:
	case GK_BPF:
		return false;
	default:
		return true;
	}
}

static uint32_t
next_flow_index(struct gk_config *gk_conf, struct gk_instance *instance)
{
	instance->scan_cur_flow_idx = (instance->scan_cur_flow_idx + 1)
		% gk_conf->flow_ht_size;
	if (likely(!instance->scan_waiting_eoc ||
			instance->scan_cur_flow_idx !=
			instance->scan_end_cycle_idx))
		return instance->scan_cur_flow_idx;

	/* Scan keys of the flow table. */
	flush_flow_table(instance, test_invalid_flow, NULL, __func__);

	/*
	 * Only clear @scan_waiting_eoc after scanning the keys of
	 * the flow table to avoid fixes of the flow table to be counted
	 * as a newly found corruption.
	 */
	instance->scan_waiting_eoc = false;
	return instance->scan_cur_flow_idx;
}

static void
log_stats(const struct gk_measurement_metrics *stats)
{
	time_t now = time(NULL);
	struct tm *p_tm, time_info;
	char str_date_time[32];
	int ret;

	if (unlikely(now == ((time_t) -1))) {
		G_LOG(ERR, "%s(): time() failed with errno=%i: %s\n",
			__func__, errno, strerror(errno));
		goto log_no_time;
	}

	p_tm = localtime_r(&now, &time_info);
	if (unlikely(p_tm == NULL)) {
		G_LOG(ERR, "%s(): localtime_r() failed with errno=%i: %s\n",
			__func__, errno, strerror(errno));
		goto log_no_time;
	}
	RTE_VERIFY(p_tm == &time_info);

	ret = strftime(str_date_time, sizeof(str_date_time),
		"%Y-%m-%d %H:%M:%S", &time_info);
	if (unlikely(ret == 0)) {
		G_LOG(ERR, "%s(): strftime() failed\n", __func__);
		goto log_no_time;
	}

	goto log;

log_no_time:
	strcpy(str_date_time, "NO TIME");
log:
	G_LOG(NOTICE,
		"Basic measurements at %s [tot_pkts_num = %"PRIu64", tot_pkts_size = %"PRIu64", pkts_num_granted = %"PRIu64", pkts_size_granted = %"PRIu64", pkts_num_request = %"PRIu64", pkts_size_request =  %"PRIu64", pkts_num_declined = %"PRIu64", pkts_size_declined =  %"PRIu64", tot_pkts_num_dropped = %"PRIu64", tot_pkts_size_dropped =  %"PRIu64", tot_pkts_num_distributed = %"PRIu64", tot_pkts_size_distributed =  %"PRIu64"]\n",
		str_date_time,
		stats->tot_pkts_num,
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
}

static int
gk_proc(void *arg)
{
	unsigned int lcore = rte_lcore_id();
	struct gk_config *gk_conf = (struct gk_config *)arg;
	unsigned int block_idx = get_block_idx(gk_conf, lcore);
	struct gk_instance *instance = &gk_conf->instances[block_idx];

	uint16_t port_front = gk_conf->net->front.id;
	uint16_t port_back = gk_conf->net->back.id;
	uint16_t rx_queue_front = instance->rx_queue_front;
	uint16_t tx_queue_front = instance->tx_queue_front;
	uint16_t rx_queue_back = instance->rx_queue_back;
	uint16_t tx_queue_back = instance->tx_queue_back;

	uint16_t tx_front_num_pkts;
	uint16_t tx_back_num_pkts;
	uint16_t tx_max_num_pkts = gk_conf->front_max_pkt_burst +
		gk_conf->back_max_pkt_burst;
	struct rte_mbuf *tx_front_pkts[tx_max_num_pkts];
	struct rte_mbuf *tx_back_pkts[tx_max_num_pkts];

	uint64_t last_measure_tsc = rte_rdtsc();
	uint64_t basic_measurement_logging_cycles =
		gk_conf->basic_measurement_logging_ms *
		rte_get_tsc_hz() / 1000;
	uint32_t scan_iter = gk_conf->flow_table_scan_iter;
	uint32_t iter_count = 0;

	G_LOG(NOTICE, "The GK block is running at tid = %u\n", gettid());

	if (needed_caps(0, NULL) < 0) {
		G_LOG(ERR, "Could not set needed capabilities\n");
		exiting = true;
	}

	gk_conf_hold(gk_conf);

	while (likely(!exiting)) {
		struct flow_entry *fe = NULL;
		uint32_t entry_idx = 0;

		tx_front_num_pkts = 0;
		tx_back_num_pkts = 0;

		if (iter_count >= scan_iter) {
			entry_idx = next_flow_index(gk_conf, instance);
			fe = &instance->ip_flow_entry_table[entry_idx];
			/*
			 * Only one prefetch is needed here because we only
			 * need the beginning of a struct flow_entry to
			 * check if it's expired.
			 */
			rte_prefetch_non_temporal(fe);

			iter_count = 0;
		} else
			iter_count++;

		process_pkts_front(port_front, rx_queue_front, lcore,
			&tx_front_num_pkts, tx_front_pkts,
			&tx_back_num_pkts, tx_back_pkts,
			instance, gk_conf);

		process_pkts_back(port_back, rx_queue_back, lcore,
			&tx_front_num_pkts, tx_front_pkts,
			&tx_back_num_pkts, tx_back_pkts,
			instance, gk_conf);

		if (fe != NULL && fe->in_use && rte_rdtsc() >= fe->expire_at) {
			rte_hash_prefetch_buckets_non_temporal(
				instance->ip_flow_hash_table,
				fe->flow_hash_val);
		} else
			fe = NULL;

		send_pkts(port_front, tx_queue_front,
			tx_front_num_pkts, tx_front_pkts);

		send_pkts(port_back, tx_queue_back,
			tx_back_num_pkts, tx_back_pkts);

		process_cmds_from_mailbox(instance, gk_conf);

		if (fe != NULL && fe->in_use && rte_rdtsc() >= fe->expire_at)
			gk_del_flow_entry_at_pos(instance, entry_idx);

		if (rte_rdtsc() - last_measure_tsc >=
				basic_measurement_logging_cycles) {
			struct gk_measurement_metrics *stats =
				&instance->traffic_stats;
			log_stats(stats);
			memset(stats, 0, sizeof(*stats));
			last_measure_tsc = rte_rdtsc();
		}
	}

	G_LOG(NOTICE, "The GK block is exiting\n");

	return gk_conf_put(gk_conf);
}

struct gk_config *
alloc_gk_conf(void)
{
	return rte_calloc("gk_config", 1, sizeof(struct gk_config), 0);
}

static void
destroy_gk_lpm(struct gk_lpm *ltbl)
{
	rib_free(&ltbl->rib);
	destroy_ipv4_lpm(ltbl->lpm);
	ltbl->lpm = NULL;
	rte_free(ltbl->fib_tbl);
	ltbl->fib_tbl = NULL;

	rib_free(&ltbl->rib6);
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
		destroy_mempool(gk_conf->instances[i].mp);

		if (gk_conf->instances[i].ip_flow_hash_table != NULL) {
			rte_hash_free(gk_conf->instances[i].
				ip_flow_hash_table);
		}

		if (gk_conf->instances[i].ip_flow_entry_table != NULL) {
			rte_free(gk_conf->instances[i].
				ip_flow_entry_table);
		}

		destroy_mailbox(&gk_conf->instances[i].mb);
	}

	if (gk_conf->lpm_tbl.fib_tbl != NULL) {
		for (ui = 0; ui < gk_conf->max_num_ipv4_rules; ui++) {
			struct gk_fib *fib = &gk_conf->lpm_tbl.fib_tbl[ui];
			if (fib->action == GK_FWD_NEIGHBOR_FRONT_NET ||
					fib->action ==
						GK_FWD_NEIGHBOR_BACK_NET) {
				destroy_neigh_hash_table(&fib->u.neigh);
			}
		}
	}

	if (gk_conf->lpm_tbl.fib_tbl6 != NULL) {
		for (ui = 0; ui < gk_conf->max_num_ipv6_rules; ui++) {
			struct gk_fib *fib = &gk_conf->lpm_tbl.fib_tbl6[ui];
			if (fib->action == GK_FWD_NEIGHBOR_FRONT_NET ||
					fib->action ==
						GK_FWD_NEIGHBOR_BACK_NET) {
				destroy_neigh_hash_table(&fib->u.neigh);
			}
		}
	}

	destroy_gk_lpm(&gk_conf->lpm_tbl);

	rte_free(gk_conf->queue_id_to_instance);
	rte_free(gk_conf->instances);
	rte_free(gk_conf->lcores);
	sol_conf_put(gk_conf->sol_conf);
	gk_conf->sol_conf = NULL;
	rte_free(gk_conf);

	return 0;
}

int
gk_conf_put(struct gk_config *gk_conf)
{
	/*
	 * Atomically decrements the atomic counter by one and returns true
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
	unsigned int num_mbuf;
	unsigned int socket_id = rte_lcore_to_socket_id(gk_conf->lcores[0]);
	struct sol_config *sol_conf;

	gk_conf->instances = rte_calloc_socket(__func__, gk_conf->num_lcores,
		sizeof(struct gk_instance), 0, socket_id);
	if (gk_conf->instances == NULL)
		goto cleanup;

	gk_conf->queue_id_to_instance = rte_malloc_socket(__func__,
		num_rx_queues * sizeof(*gk_conf->queue_id_to_instance), 0, socket_id);
	if (gk_conf->queue_id_to_instance == NULL)
		goto cleanup;

	for(i = 0; i < num_rx_queues; i++)
		gk_conf->queue_id_to_instance[i] = -1;

	/*
	 * Set up the GK LPM table. We assume that
	 * all the GK instances are running on the same socket.
	 */
	ret = setup_gk_lpm(gk_conf, socket_id);
	if (ret < 0)
		goto cleanup;

	num_mbuf = calculate_mempool_config_para("gk", gk_conf->net,
		gk_conf->front_max_pkt_burst + gk_conf->back_max_pkt_burst +
		(gk_conf->net->front.total_pkt_burst +
		gk_conf->net->back.total_pkt_burst + gk_conf->num_lcores - 1) /
		gk_conf->num_lcores);

	sol_conf = gk_conf->sol_conf;
	for (i = 0; i < gk_conf->num_lcores; i++) {
		unsigned int lcore = gk_conf->lcores[i];
		struct gk_instance *inst_ptr = &gk_conf->instances[i];

		inst_ptr->mp = create_pktmbuf_pool("gk", lcore, num_mbuf);
		if (inst_ptr->mp == NULL)
			goto cleanup;

		/* Set up queue identifiers for RSS. */

		ret = get_queue_id(&gk_conf->net->front, QUEUE_TYPE_RX, lcore,
			inst_ptr->mp);
		if (ret < 0) {
			G_LOG(ERR, "Cannot assign an RX queue for the front interface for lcore %u\n",
				lcore);
			goto cleanup;
		}
		inst_ptr->rx_queue_front = ret;
		gk_conf->queue_id_to_instance[ret] = i;

		ret = get_queue_id(&gk_conf->net->front, QUEUE_TYPE_TX, lcore,
			NULL);
		if (ret < 0) {
			G_LOG(ERR, "Cannot assign a TX queue for the front interface for lcore %u\n",
				lcore);
			goto cleanup;
		}
		inst_ptr->tx_queue_front = ret;

		ret = get_queue_id(&gk_conf->net->back, QUEUE_TYPE_RX, lcore,
			inst_ptr->mp);
		if (ret < 0) {
			G_LOG(ERR, "Cannot assign an RX queue for the back interface for lcore %u\n",
				lcore);
			goto cleanup;
		}
		inst_ptr->rx_queue_back = ret;

		ret = get_queue_id(&gk_conf->net->back, QUEUE_TYPE_TX, lcore,
			NULL);
		if (ret < 0) {
			G_LOG(ERR, "Cannot assign a TX queue for the back interface for lcore %u\n",
				lcore);
			goto cleanup;
		}
		inst_ptr->tx_queue_back = ret;

		if (gk_conf->gk_sol_map[i] >= (unsigned int)sol_conf->num_lcores) {
			G_LOG(ERR, "Invalid index (%u) of sol_conf->instances[] for lcore %u\n",
				gk_conf->gk_sol_map[i], lcore);
			goto cleanup;
		}

		inst_ptr->sol_inst = &sol_conf->instances[gk_conf->gk_sol_map[i]];

		/* Setup the GK instance at @lcore. */
		ret = setup_gk_instance(lcore, gk_conf);
		if (ret < 0) {
			G_LOG(ERR,
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

	if (net_conf == NULL || gk_conf == NULL || sol_conf == NULL) {
		ret = -1;
		goto out;
	}

	for (i = 0; i < gk_conf->num_lcores; i++) {
		log_ratelimit_state_init(gk_conf->lcores[i],
			gk_conf->log_ratelimit_interval_ms,
			gk_conf->log_ratelimit_burst,
			gk_conf->log_level, "GK");
	}

	if (!net_conf->back_iface_enabled) {
		G_LOG(ERR, "Back interface is required\n");
		ret = -1;
		goto out;
	}

	if (!(gk_conf->front_max_pkt_burst > 0 &&
			gk_conf->back_max_pkt_burst > 0)) {
		ret = -1;
		goto out;
	}

	if (gk_conf->gk_sol_map == NULL) {
		G_LOG(ERR, "GK-to-SOL mapping is required for initialization\n");
		ret = -1;
		goto out;
	}

	gk_conf->net = net_conf;
	sol_conf_hold(sol_conf);
	gk_conf->sol_conf = sol_conf;

	if (gk_conf->num_lcores <= 0)
		goto success;

	ret = net_launch_at_stage1(
		net_conf, gk_conf->num_lcores, gk_conf->num_lcores,
		gk_conf->num_lcores, gk_conf->num_lcores, gk_stage1, gk_conf);
	if (ret < 0)
		goto put_sol;

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
put_sol:
	gk_conf->sol_conf = NULL;
	sol_conf_put(sol_conf);
out:
	return ret;

success:
	rte_atomic32_init(&gk_conf->ref_cnt);
	return 0;
}

struct mailbox *
get_responsible_gk_mailbox(uint32_t flow_hash_val,
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
	rss_hash_val = flow_hash_val % gk_conf->rss_conf_front.reta_size;

	/*
	 * Identify which GK block is responsible for the
	 * pair <Src, Dst> in the decision.
	 */
	idx = rss_hash_val / RTE_RETA_GROUP_SIZE;
	shift = rss_hash_val % RTE_RETA_GROUP_SIZE;
	queue_id = gk_conf->rss_conf_front.reta_conf[idx].reta[shift];
	block_idx = gk_conf->queue_id_to_instance[queue_id];

	if (block_idx == -1)
		G_LOG(ERR, "Wrong RSS configuration for GK blocks\n");
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
		G_LOG(ERR, "Failed to flush flow table: both source and destination prefixes are NULL\n");
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
			G_LOG(WARNING,
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

int
gk_log_flow_state(const char *src_addr,
	const char *dst_addr, struct gk_config *gk_conf)
{
	int ret;
	uint32_t flow_hash_val;
	struct ipaddr src;
	struct ipaddr dst;
	struct ip_flow flow;
	struct mailbox *mb;
	struct gk_cmd_entry *entry;

	if (src_addr == NULL) {
		G_LOG(ERR, "gk: failed to log flow state - source address is NULL\n");
		return -1;
	}
	if (dst_addr == NULL) {
		G_LOG(ERR, "gk: failed to log flow state - destination address is NULL\n");
		return -1;
	}
	if (gk_conf == NULL) {
		G_LOG(ERR, "gk: failed to log flow state - gk_conf is NULL\n");
		return -1;
	}

	ret = convert_str_to_ip(src_addr, &src);
	if (ret < 0) {
		G_LOG(ERR, "gk: failed to log flow state - source address (%s) is invalid\n",
			src_addr);
		return -1;
	}

	ret = convert_str_to_ip(dst_addr, &dst);
	if (ret < 0) {
		G_LOG(ERR, "gk: failed to log flow state - destination address (%s) is invalid\n",
			dst_addr);
		return -1;
	}

	if (unlikely(src.proto != dst.proto)) {
		G_LOG(ERR, "gk: failed to log flow state - source (%s) and destination (%s) addresses don't have the same IP type\n",
			src_addr, dst_addr);
		return -1;
	}

	if (unlikely(src.proto != RTE_ETHER_TYPE_IPV4 && src.proto !=
			RTE_ETHER_TYPE_IPV6)) {
		G_LOG(ERR, "gk: failed to log flow state - source (%s) and destination (%s) addresses don't have valid IP type %hu\n",
			src_addr, dst_addr, src.proto);
		return -1;
	}

	memset(&flow, 0, sizeof(flow));

	flow.proto = src.proto;
	if (flow.proto == RTE_ETHER_TYPE_IPV4) {
		flow.f.v4.src = src.ip.v4;
		flow.f.v4.dst = dst.ip.v4;
	} else {
		flow.f.v6.src = src.ip.v6;
		flow.f.v6.dst = dst.ip.v6;
	}

	flow_hash_val = rss_ip_flow_hf(&flow, 0, 0);

	mb = get_responsible_gk_mailbox(flow_hash_val, gk_conf);
	if (mb == NULL) {
		G_LOG(ERR, "gk: failed to get responsible GK mailbox to log flow state that matches src_addr=%s and dst_addr=%s\n",
			src_addr, dst_addr);
		return -1;
	}

	entry = mb_alloc_entry(mb);
	if (entry == NULL) {
		G_LOG(WARNING,
			"gk: failed to allocate an entry for the mailbox of the GK block to log flow state that matches src_addr=%s and dst_addr=%s\n",
			src_addr, dst_addr);
		return -1;
	}

	entry->op = GK_LOG_FLOW_STATE;
	entry->u.log.flow = flow;
	entry->u.log.flow_hash_val = flow_hash_val;

	mb_send_entry(mb, entry);

	return 0;
}

static int
notify_gk_instance(struct gk_instance *instance, rte_atomic32_t *done_counter,
	fill_in_gk_cmd_entry_t fill_f, void *arg)
{
	int ret;
	struct mailbox *mb = &instance->mb;
	struct gk_cmd_entry *entry = mb_alloc_entry(mb);
	if (entry == NULL) {
		G_LOG(ERR,
			"Failed to allocate a `struct gk_cmd_entry` entry at %s()\n",
			__func__);
		return -1;
	}

	fill_f(entry, done_counter, arg);

	ret = mb_send_entry(mb, entry);
	if (ret < 0) {
		G_LOG(ERR,
			"Failed to send a `struct gk_cmd_entry` entry at %s()\n",
			__func__);
		return -1;
	}

	return 0;
}

/*
 * XXX #70 What we are doing here is analogous to RCU's synchronize_rcu(),
 * what suggests that we may be able to profit from RCU. But we are going
 * to postpone that until we have a better case to bring RCU to Gatekeeper.
 */
void
synchronize_gk_instances(struct gk_config *gk_conf,
	fill_in_gk_cmd_entry_t fill_f, void *arg)
{
	int loop, num_succ_notified_inst = 0;
	bool is_succ_notified[gk_conf->num_lcores];
	rte_atomic32_t done_counter = RTE_ATOMIC32_INIT(0);

	/* The maximum number of times to try to notify the GK instances. */
	const int MAX_NUM_NOTIFY_TRY = 3;

	memset(is_succ_notified, false, sizeof(is_succ_notified));

	for (loop = 0; loop < MAX_NUM_NOTIFY_TRY; loop++) {
		int i;

		/* Notify all GK instances. */
		for (i = 0; i < gk_conf->num_lcores; i++) {
			int ret;

			if (is_succ_notified[i])
				continue;

			ret = notify_gk_instance(&gk_conf->instances[i],
				&done_counter, fill_f, arg);
			if (unlikely(ret < 0))
				continue;

			is_succ_notified[i] = true;
			num_succ_notified_inst++;
			if (num_succ_notified_inst >= gk_conf->num_lcores)
				goto finish_notify;
		}
	}

finish_notify:

	if (num_succ_notified_inst != gk_conf->num_lcores) {
		G_LOG(WARNING,
			"%s() successfully notified only GK %d/%d instances\n",
			__func__, num_succ_notified_inst, gk_conf->num_lcores);
	}

	/* Wait for all GK instances to synchronize. */
	while (rte_atomic32_read(&done_counter) < num_succ_notified_inst)
		rte_pause();
}
