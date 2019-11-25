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

#include <linux/icmp.h>
#include <linux/icmpv6.h>

#include "gatekeeper_lls.h"

#include "bpf.h"
#include "co.h"

static struct gk_co *
get_next_co(struct gk_co *this_co)
{
	/*
	 * It is unlikely because as long as there is more than
	 * one working coroutine, there is at least 50% chance that
	 * @this_co is not the last working coroutine.
	 */
	if (unlikely(this_co->co_list.next == &this_co->work->working_cos)) {
		/* @this_co is the last working co. */
		return list_first_entry(&this_co->work->working_cos,
			struct gk_co, co_list);
	}
	return list_next_entry(this_co, co_list);
}

static void
yield_next(struct gk_co *this_co)
{
	struct gk_co *next_co = get_next_co(this_co);
	if (unlikely(this_co == next_co))
		return;
	coro_transfer(&this_co->coro, &next_co->coro);
}

/*
 * If @task is added to @this_co->task_queue without a proper @task->task_hash,
 * @task must be rescheduled once the proper @task->task_hash becomes known
 * in order to avoid race conditions related to the proper @task->task_hash.
 *
 * NOTICE: while a task is running without a proper @task->task_hash,
 * the task must not use the leftover available because the task is likely
 * running under a task hash that is different of its proper @task->task_hash.
 */
static void
reschedule_task(struct gk_co *this_co, struct gk_co_task *task)
{
	struct gk_co_work *work = this_co->work;
	struct gk_co *task_owner_co = get_task_owner_co(work, task);

	__schedule_task(task_owner_co, task);

	if (list_poison(&task_owner_co->co_list))
		list_add_tail(&task_owner_co->co_list, &work->working_cos);
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
		if (pkt_len < ether_len + sizeof(*ip6_hdr)) {
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

static int
drop_packet_front(struct rte_mbuf *pkt, struct gk_instance *instance)
{
	instance->traffic_stats.tot_pkts_num_dropped++;
	instance->traffic_stats.tot_pkts_size_dropped +=
		rte_pktmbuf_pkt_len(pkt);

	return drop_packet(pkt);
}

static int
parse_front_pkt(struct gk_co *this_co,
	struct ipacket *packet, struct rte_mbuf *pkt)
{
	struct gk_co_work *work = this_co->work;
	int ret;

	/* TODO Does this prefetch improve performance?
	rte_mbuf_prefetch_part1_non_temporal(pkt);
	yield_next(this_co);
	*/
       /*
        * This prefetch is enough to load Ethernet header (14 bytes),
        * optional Ethernet VLAN header (8 bytes), and either
        * an IPv4 header without options (20 bytes), or
        * an IPv6 header without options (40 bytes).
        * IPv4: 14 + 8 + 20 = 42
        * IPv6: 14 + 8 + 40 = 62
	rte_prefetch_non_temporal(rte_pktmbuf_mtod_offset(pkt, void *, 0));
	yield_next(this_co);
        */

	ret = extract_packet_info(pkt, packet);
	if (ret < 0) {
		if (likely(packet->flow.proto == RTE_ETHER_TYPE_ARP)) {
			struct gk_measurement_metrics *stats =
				&work->instance->traffic_stats;

			stats->tot_pkts_num_distributed++;
			stats->tot_pkts_size_distributed +=
				rte_pktmbuf_pkt_len(pkt);

			work->front_arp_bufs[work->front_num_arp++] = pkt;
			return -1;
		}

		/* Drop non-IP and non-ARP packets. */
		drop_packet_front(pkt, work->instance);
		return -1;
	}

	if (unlikely((packet->flow.proto == RTE_ETHER_TYPE_IPV4 &&
				!work->front_ipv4_configured) ||
			(packet->flow.proto == RTE_ETHER_TYPE_IPV6 &&
				!work->front_ipv6_configured))) {
		drop_packet_front(pkt, work->instance);
		return -1;
	}

	return 0;
}

#define	START_PRIORITY		 (38)
/* Set @START_ALLOWANCE as the double size of a large DNS reply. */
#define	START_ALLOWANCE		 (8)

static void
initialize_flow_entry(struct flow_entry *fe, struct ip_flow *flow,
	uint32_t flow_hash_val, struct gk_fib *grantor_fib)
{
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

/*
 * When a flow entry is at request state, all the GK block processing
 * that entry does is to:
 * (1) compute the priority of the packet.
 * (2) encapsulate the packet as a request.
 * (3) put this encapsulated packet in the request queue.
 */
static void
gk_process_request(struct gk_co *this_co, struct flow_entry *fe,
	struct ipacket *packet)
{
	int ret;
	uint64_t now = rte_rdtsc();
	uint8_t priority = priority_from_delta_time(now,
		fe->u.request.last_packet_seen_at);
	struct rte_mbuf *pkt = packet->pkt;
	struct gk_co_work *work = this_co->work;
	struct gatekeeper_if *back = &work->gk_conf->net->back;
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
	priority += PRIORITY_REQ_MIN;
	if (unlikely(priority > PRIORITY_MAX))
		priority = PRIORITY_MAX;

	/* The assigned priority is @priority. */

	/* Encapsulate the packet as a request. */
	ret = encapsulate(pkt, priority, back, &fib->u.grantor.gt_addr);
	if (ret < 0)
		goto drop_pkt;

	eth_cache = fib->u.grantor.eth_cache;
	RTE_VERIFY(eth_cache != NULL);
	/* If needed, packet header space was adjusted by encapsulate(). */
	if (pkt_copy_cached_eth_header(pkt, eth_cache, back->l2_len_out))
		goto drop_pkt;

	pkt->udata64 = priority;
	work->front_req_bufs[work->front_num_req++] = pkt;
	return;

drop_pkt:
	drop_packet_front(pkt, work->instance);
}

static void
gk_process_granted(struct gk_co *this_co, struct flow_entry *fe,
	struct ipacket *packet)
{
	int ret;
	bool renew_cap;
	uint8_t priority = PRIORITY_GRANTED;
	uint64_t now = rte_rdtsc();
	struct rte_mbuf *pkt = packet->pkt;
	struct gk_fib *fib = fe->grantor_fib;
	struct gk_co_work *work = this_co->work;
	struct gatekeeper_if *back = &work->gk_conf->net->back;
	struct gk_measurement_metrics *stats;
	struct ether_cache *eth_cache;
	uint32_t pkt_len;

	if (now >= fe->u.granted.cap_expire_at) {
		reinitialize_flow_entry(fe, now);
		return gk_process_request(this_co, fe, packet);
	}

	if (now >= fe->u.granted.budget_renew_at) {
		fe->u.granted.budget_renew_at = now + cycles_per_sec;
		fe->u.granted.budget_byte =
			(uint64_t)fe->u.granted.tx_rate_kib_cycle * 1024;
	}

	stats = &work->instance->traffic_stats;

	pkt_len = rte_pktmbuf_pkt_len(pkt);
	if (pkt_len > fe->u.granted.budget_byte) {
		stats->pkts_num_declined++;
		stats->pkts_size_declined += pkt_len;
		goto drop_pkt;
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
	ret = encapsulate(pkt, priority, back, &fib->u.grantor.gt_addr);
	if (ret < 0)
		goto drop_pkt;

	eth_cache = fib->u.grantor.eth_cache;
	RTE_VERIFY(eth_cache != NULL);
	/* If needed, packet header space was adjusted by encapsulate(). */
	if (pkt_copy_cached_eth_header(pkt, eth_cache, back->l2_len_out))
		goto drop_pkt;

	stats->pkts_num_granted++;
	stats->pkts_size_granted += pkt_len;
	work->tx_back_pkts[work->tx_back_num_pkts++] = pkt;
	return;

drop_pkt:
	drop_packet_front(pkt, work->instance);
}

static void
gk_process_declined(struct gk_co *this_co, struct flow_entry *fe,
	struct ipacket *packet)
{
	uint64_t now = rte_rdtsc();
	struct gk_co_work *work = this_co->work;
	struct gk_measurement_metrics *stats;

	if (unlikely(now >= fe->u.declined.expire_at)) {
		reinitialize_flow_entry(fe, now);
		return gk_process_request(this_co, fe, packet);
	}

	stats = &work->instance->traffic_stats;
	stats->pkts_num_declined++;
	stats->pkts_size_declined += rte_pktmbuf_pkt_len(packet->pkt);
	drop_packet_front(packet->pkt, work->instance);
}

static void
gk_process_bpf(struct gk_co *this_co, struct flow_entry *fe,
	struct ipacket *packet)
{
	struct rte_mbuf *pkt = packet->pkt;
	struct gk_co_work *work = this_co->work;
	struct gk_config *gk_conf = work->gk_conf;
	struct gk_measurement_metrics *stats;
	uint64_t bpf_ret;
	int program_index, rc;
	uint64_t now = rte_rdtsc();

	if (unlikely(now >= fe->u.bpf.expire_at))
		goto expired;

	program_index = fe->program_index;
	rc = gk_bpf_decide_pkt(gk_conf, program_index, fe, packet, now,
		&bpf_ret);
	if (unlikely(rc != 0)) {
		GK_LOG(WARNING,
			"The BPF program at index %u failed to run its function pkt\n",
			program_index);
		goto expired;
	}

	stats = &work->instance->traffic_stats;
	switch (bpf_ret) {
	case GK_BPF_PKT_RET_FORWARD: {
		struct ether_cache *eth_cache =
			fe->grantor_fib->u.grantor.eth_cache;
		RTE_VERIFY(eth_cache != NULL);
		/*
		 * If needed, encapsulate() already adjusted
		 * packet header space.
		 */
		if (pkt_copy_cached_eth_header(pkt, eth_cache,
				gk_conf->net->back.l2_len_out))
			goto drop_pkt;

		stats->pkts_num_granted++;
		stats->pkts_size_granted += rte_pktmbuf_pkt_len(pkt);
		work->tx_back_pkts[work->tx_back_num_pkts++] = pkt;
		return;
	}
	case GK_BPF_PKT_RET_DECLINE:
		stats->pkts_num_declined++;
		stats->pkts_size_declined += rte_pktmbuf_pkt_len(pkt);
		goto drop_pkt;
	case GK_BPF_PKT_RET_ERROR:
		GK_LOG(WARNING,
			"The function pkt of the BPF program at index %u returned GK_BPF_PKT_RET_ERROR\n",
			program_index);
		goto drop_pkt;
	default:
		GK_LOG(WARNING,
			"The function pkt of the BPF program at index %u returned an invalid return: %" PRIu64 "\n",
			program_index, bpf_ret);
		goto drop_pkt;
	}

	rte_panic("Unexpected condition at %s()", __func__);

expired:
	reinitialize_flow_entry(fe, now);
	return gk_process_request(this_co, fe, packet);

drop_pkt:
	drop_packet_front(pkt, work->instance);
}

static void
process_flow_entry(struct gk_co *this_co, struct flow_entry *fe,
	struct ipacket *packet)
{
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
		return gk_process_request(this_co, fe, packet);

	case GK_GRANTED:
		return gk_process_granted(this_co, fe, packet);

	case GK_DECLINED:
		return gk_process_declined(this_co, fe, packet);

	case GK_BPF:
		return gk_process_bpf(this_co, fe, packet);

	default:
		GK_LOG(ERR, "Unknown flow state: %d\n", fe->state);
		drop_packet_front(packet->pkt, this_co->work->instance);
		return;
	}

	rte_panic("Unexpected condition at %s()\n", __func__);
}

typedef int (*packet_drop_cb_func)(struct rte_mbuf *pkt,
	struct gk_instance *instance);

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

static void
forward_pkt_to_back(struct ipacket *packet, struct ether_cache *eth_cache,
	struct gk_co_work *work)
{
	struct rte_mbuf *pkt = packet->pkt;
	struct gatekeeper_if *front = &work->gk_conf->net->front;
	struct gatekeeper_if *back = &work->gk_conf->net->back;

	if (adjust_pkt_len(pkt, back, 0) == NULL ||
			pkt_copy_cached_eth_header(pkt, eth_cache,
				back->l2_len_out)) {
		drop_packet_front(pkt, work->instance);
		return;
	}

	if (update_ip_hop_count(front, packet,
			&work->tx_front_num_pkts, work->tx_front_pkts,
			&work->instance->front_icmp_rs, work->instance,
			drop_packet_front) < 0)
		return;

	work->tx_back_pkts[work->tx_back_num_pkts++] = pkt;
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

static struct flow_entry *
lookup_fe_from_lpm(struct ipacket *packet, uint32_t ip_flow_hash_val,
	struct gk_co_work *work)
{
	struct rte_mbuf *pkt = packet->pkt;

	/*
	 * A prefetch is not needed here because current deployments of
	 * Gatekeeper servers have only a couple of FIB entries forwarding
	 * traffic from front to back interfaces.
	 */
	struct gk_fib *fib = look_up_fib(&work->gk_conf->lpm_tbl,
		&packet->flow);

	if (fib == NULL || fib->action == GK_FWD_NEIGHBOR_FRONT_NET) {
		struct gk_measurement_metrics *stats =
			&work->instance->traffic_stats;
		if (packet->flow.proto == RTE_ETHER_TYPE_IPV4) {
			stats->tot_pkts_num_distributed++;
			stats->tot_pkts_size_distributed +=
				rte_pktmbuf_pkt_len(pkt);
			add_pkt_acl(&work->front_acl4, pkt);
		} else if (likely(packet->flow.proto ==
				RTE_ETHER_TYPE_IPV6)) {
			stats->tot_pkts_num_distributed++;
			stats->tot_pkts_size_distributed +=
				rte_pktmbuf_pkt_len(pkt);
			add_pkt_acl(&work->front_acl6, pkt);
		} else {
			print_flow_err_msg(&packet->flow,
				"gk: failed to get the fib entry");
			drop_packet_front(pkt, work->instance);
		}
		return NULL;
	}

	switch (fib->action) {
	case GK_FWD_GRANTOR: {
		struct flow_entry *fe = &work->temp_fes[work->temp_fes_num++];
		initialize_flow_entry(fe, &packet->flow, ip_flow_hash_val, fib);
		return fe;
	}

	case GK_FWD_GATEWAY_BACK_NET: {
		/*
		 * The entry instructs to forward its packets to
		 * the gateway in the back network.
		 */
		struct ether_cache *eth_cache = fib->u.gateway.eth_cache;
		RTE_VERIFY(eth_cache != NULL);
		forward_pkt_to_back(packet, eth_cache, work);
		return NULL;
	}

	case GK_FWD_NEIGHBOR_BACK_NET: {
		/*
		 * The entry instructs to forward its packets to
		 * the neighbor in the back network.
		 */
		struct ether_cache *eth_cache =
			(packet->flow.proto == RTE_ETHER_TYPE_IPV4)
				? lookup_ether_cache(&fib->u.neigh,
					&packet->flow.f.v4.dst)
				: lookup_ether_cache(&fib->u.neigh6,
					&packet->flow.f.v6.dst);
		RTE_VERIFY(eth_cache != NULL);
		forward_pkt_to_back(packet, eth_cache, work);
		return NULL;
	}

	case GK_DROP:
		/* FALLTHROUGH */
	default:
		drop_packet_front(pkt, work->instance);
		return NULL;
	}

	return NULL;
}

static void
prefetch_and_yield(void *addr, void *this_co)
{
	rte_prefetch_non_temporal(addr);
	yield_next(this_co);
}

static void
gk_co_process_front_pkt_final(struct gk_co *this_co, struct gk_co_task *task)
{
	struct ipacket *packet = task->task_arg;
	struct gk_co_work *work = this_co->work;
	uint32_t ip_flow_hash_val = task->task_hash;
	struct flow_entry *fe_leftover =
		get_fe_leftover(work, ip_flow_hash_val);
	struct flow_entry *fe;
	int ret;

	/* Is leftover useful? */
	if (fe_leftover != NULL &&
			fe_leftover->flow_hash_val == ip_flow_hash_val &&
			ip_flow_cmp_eq(&fe_leftover->flow,
				&packet->flow, 0) == 0) {
		/* Jackpot! Deal with @pkt right away. */
		process_flow_entry(this_co, fe_leftover, packet);
		return;
	}

	/* Look up flow entry. */
	ret = rte_hash_lookup_and_yield_with_hash(
		work->instance->ip_flow_hash_table, &packet->flow,
		ip_flow_hash_val, prefetch_and_yield, this_co);
	if (ret >= 0) {
		fe = &work->instance->ip_flow_entry_table[ret];
		/* TODO Break this prefetch into part1 and part2. */
		prefetch_flow_entry(fe);
		yield_next(this_co);
		process_flow_entry(this_co, fe, packet);
		save_fe_leftover(work, fe);
		return;
	}
	if (unlikely(ret != -ENOENT)) {
		char err_msg[1024];

		ret = snprintf(err_msg, sizeof(err_msg),
			"gk: failed to look up flow state at %s with lcore %u: %i\n",
			__func__, rte_lcore_id(), ret);

		RTE_VERIFY(ret > 0 && ret < (int)sizeof(err_msg));
		print_flow_err_msg(&packet->flow, err_msg);
		return;
	}

	fe = lookup_fe_from_lpm(packet, ip_flow_hash_val, work);
	if (fe == NULL)
		return;
	process_flow_entry(this_co, fe, packet);
	save_fe_leftover(work, fe);
}

void
gk_co_process_front_pkt_software_rss(struct gk_co *this_co,
	struct gk_co_task *task)
{
	struct ipacket *packet = task->task_arg;

	if (parse_front_pkt(this_co, packet, packet->pkt) != 0)
		return;

	/* Finish up the work with the correct hash value. */
	task->task_hash = rss_ip_flow_hf(&packet->flow, 0, 0);
	task->task_func = gk_co_process_front_pkt_final;
	reschedule_task(this_co, task);
}

void
gk_co_process_front_pkt(struct gk_co *this_co, struct gk_co_task *task)
{
	struct ipacket packet;

	if (parse_front_pkt(this_co, &packet, task->task_arg) != 0)
		return;
	task->task_arg = &packet;
	gk_co_process_front_pkt_final(this_co, task);
}

static void
gk_co_scan_flow_table_final(struct gk_co *this_co, struct gk_co_task *task)
{
	struct gk_co_work *work = this_co->work;
	struct flow_entry *fe = task->task_arg;
	struct flow_entry **leftover_bucket = get_fe_leftover_bucket(work, fe);

	RTE_VERIFY(work->del_fe == NULL);
	work->del_fe = fe;

	/* Deal with the leftover. */
	if (unlikely(*leftover_bucket == fe)) {
		/* One does not need to look up again. */
		return;
	}
	*leftover_bucket = fe;

	/* Prefetch buckets to remove the flow entry later. */
	rte_hash_lookup_and_yield_with_hash(work->instance->ip_flow_hash_table,
		&fe->flow, fe->flow_hash_val, prefetch_and_yield, this_co);
}

static bool
is_flow_expired(struct flow_entry *fe, uint64_t now)
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

		/*
		 * A request entry is considered expired if it is not
		 * doubling its waiting time. We use +2 instead of +1 in
		 * the test below to account for random delays in the network.
		 */
		return priority_from_delta_time(now,
			fe->u.request.last_packet_seen_at) >
			fe->u.request.last_priority + 2;
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

void
gk_co_scan_flow_table(struct gk_co *this_co, struct gk_co_task *task)
{
	struct flow_entry *fe = task->task_arg;

	/*
	 * Only one prefetch is needed here because one only needs
	 * the beginning of a struct flow_entry to
	 * check if it's expired.
	 */
	rte_prefetch_non_temporal(fe);
	yield_next(this_co);

	if (!fe->in_use || !is_flow_expired(fe, rte_rdtsc()))
		return;

	/* Finish up the work with the correct hash value. */
	task->task_hash = fe->flow_hash_val;
	task->task_func = gk_co_scan_flow_table_final;
	reschedule_task(this_co, task);
}

static struct gk_co_task *
next_task(struct gk_co *this_co)
{
	while (true) {
		struct gk_co *next_co;

		/*
		 * This test is likely because if @this_co has at least
		 * one task, there's at least 50% that it will be true because
		 * this function is called twice.
		 */
		if (likely(!list_empty(&this_co->task_queue))) {
			/*
			 * @this_co has assigned tasks.
			 * Return the first assigned task.
			 */
			struct gk_co_task *task = list_first_entry(
				&this_co->task_queue, struct gk_co_task,
				task_list);
			list_del(&task->task_list);
			return task;
		}

		/* There is no more tasks assigned to @this_co. */

		next_co = get_next_co(this_co);

		/* Make @this_co idle. */
		list_del(&this_co->co_list);

		/* Transfer control to another coroutine. */
		if (likely(this_co != next_co)) {
			/*
			 * @this_co is NOT the last working coroutine.
			 * Yield to the next coroutine.
			 */
			coro_transfer(&this_co->coro, &next_co->coro);
		} else {
			/*
			 * No more work and no more working coroutines;
			 * @this_co is the last working coroutine.
			 * Return to the main coroutine.
			 */
			coro_transfer(&this_co->coro,
				&this_co->work->instance->coro_root);
		}
	}
}

void
gk_co_main(void *arg)
{
	struct gk_co *this_co = arg;
	struct gk_co_task *task = next_task(this_co);

	while (likely(task != NULL)) {
		task->task_func(this_co, task);
		task = next_task(this_co);
	}

	rte_panic("%s() terminated\n", __func__);
}
