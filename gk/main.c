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

#include "co.h"

int gk_logtype;

/*
 * TODO A copy of this function is available in gk/co.c,
 * so drop it when possible.
 */
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
 * TODO A copy of this function is available in gk/co.c,
 * so drop it when possible.
 */
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
 * TODO A copy of this function is available in gk/co.c,
 * so drop it when possible.
 */
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

/*
 * TODO A copy of this function is available in gk/co.c,
 * so drop it when possible.
 */
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

/*
 * TODO A copy of this typedef is available in gk/co.c,
 * so drop it when possible.
 */
typedef int (*packet_drop_cb_func)(struct rte_mbuf *pkt,
	struct gk_instance *instance);

/*
 * TODO A copy of this function is available in gk/co.c,
 * so drop it when possible.
 */
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

/*
 * TODO A copy of this function is available in gk/co.c,
 * so drop it when possible.
 */
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

static int
gk_del_flow_entry_from_hash(struct gk_instance *instance, struct flow_entry *fe)
{

	int ret = rte_hash_del_key_with_hash(instance->ip_flow_hash_table,
		&fe->flow, fe->flow_hash_val);
	if (likely(ret >= 0)) {
		memset(fe, 0, sizeof(*fe));

		if (instance->num_scan_del > 0)
			instance->num_scan_del--;
	} else {
		GK_LOG(ERR,
			"The GK block failed to delete a key from hash table at %s: %s\n",
			__func__, strerror(-ret));
	}

	return ret;
}

static void
free_cos(struct gk_co *cos, unsigned int num)
{
	unsigned int i;

	if (cos == NULL)
		return;

	for (i = 0; i < num; i++) {
		struct gk_co *co = &cos[i];

		if (co->stack.sptr == NULL)
			continue;

		/* Free @co. */
		coro_destroy(&co->coro);
		coro_stack_free(&co->stack);
	}

	rte_free(cos);
}

static struct gk_co *
alloc_cos(unsigned int num, unsigned int stack_size_byte)
{
	unsigned int stack_size_ptr = stack_size_byte / sizeof(void *);
	unsigned int i;

	struct gk_co *cos = rte_calloc(__func__, num, sizeof(*cos), 0);
	if (cos == NULL)
		return NULL;

	for (i = 0; i < num; i++) {
		struct gk_co *co = &cos[i];

		if (unlikely(!coro_stack_alloc(&co->stack, stack_size_ptr))) {
			free_cos(cos, num);
			return NULL;
		}

		coro_create(&co->coro, gk_co_main, co,
			co->stack.sptr, co->stack.ssze);
		INIT_LIST_HEAD_WITH_POISON(&co->co_list);
		INIT_LIST_HEAD(&co->task_queue);
		co->work = NULL;
	}

	return cos;
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

	ret = init_mailbox("gk", gk_conf->mailbox_max_entries_exp,
		sizeof(struct gk_cmd_entry), gk_conf->mailbox_mem_cache_size,
		lcore_id, &instance->mb);
    	if (ret < 0)
		goto flow_entry;

	coro_create(&instance->coro_root, NULL, NULL, NULL, 0);

	/* Allocate coroutines. */
	instance->cos = alloc_cos(gk_conf->co_max_num,
		gk_conf->co_stack_size_kb * 1024);
	if (instance->cos == NULL) {
		GK_LOG(ERR,
			"The GK block can't allocate coroutines at lcore %u\n",
			lcore_id);
		ret = -1;
		goto coro_root;
	}

	tb_ratelimit_state_init(&instance->front_icmp_rs,
		gk_conf->front_icmp_msgs_per_sec,
		gk_conf->front_icmp_msgs_burst);
	tb_ratelimit_state_init(&instance->back_icmp_rs,
		gk_conf->back_icmp_msgs_per_sec,
		gk_conf->back_icmp_msgs_burst);

	ret = 0;
	goto out;

coro_root:
	coro_destroy(&instance->coro_root);
/*mailbox:*/
	destroy_mailbox(&instance->mb);
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
			gk_del_flow_entry_from_hash(instance, fe);
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
print_flow_state(struct flow_entry *fe)
{
	int ret;
	char ip[MAX_INET_ADDRSTRLEN];
	char state_msg[1024];

	if (unlikely(fe->grantor_fib == NULL)) {
		ret = snprintf(state_msg, sizeof(state_msg),
			"gk: flow entry points to an NULL FIB entry in the flow table at %s with lcore %u, there is a bug in the GK block\n",
			__func__, rte_lcore_id());
		goto out;
	} else if (unlikely(fe->grantor_fib->action !=
			GK_FWD_GRANTOR)) {
		ret = snprintf(state_msg, sizeof(state_msg),
			"gk: flow with invalid FIB entry [action: %hhu] in the flow table at %s with lcore %u, there is a bug in the GK block\n",
			fe->grantor_fib->action, __func__, rte_lcore_id());
		goto out;
	}

	ret = convert_ip_to_str(&fe->grantor_fib->u.grantor.gt_addr,
		ip, sizeof(ip));
	if (ret < 0) {
		ret = snprintf(state_msg, sizeof(state_msg),
			"gk: flow with invalid FIB entry [action: %hhu] in the flow table at %s with lcore %u - failed to convert the Grantor IP address to string",
			fe->grantor_fib->action, __func__, rte_lcore_id());
		goto out;
	}

	switch (fe->state) {
	case GK_REQUEST:
		ret = snprintf(state_msg, sizeof(state_msg),
			"gk: log the flow state [state: GK_REQUEST (%hhu), flow hash value: %u, last_packet_seen_at: %"PRIx64", last_priority: %hhu, allowance: %hhu, grantor_ip: %s] in the flow table at %s with lcore %u",
			fe->state, fe->flow_hash_val,
			fe->u.request.last_packet_seen_at,
			fe->u.request.last_priority, fe->u.request.allowance,
			ip, __func__, rte_lcore_id());
		break;
	case GK_GRANTED:
		ret = snprintf(state_msg, sizeof(state_msg),
			"gk: log the flow state [state: GK_GRANTED (%hhu), flow hash value: %u, cap_expire_at: %"PRIx64", budget_renew_at: %"PRIx64", tx_rate_kib_cycle: %u, budget_byte: %"PRIx64", send_next_renewal_at: %"PRIx64", renewal_step_cycle: %"PRIx64", grantor_ip: %s] in the flow table at %s with lcore %u",
			fe->state, fe->flow_hash_val,
			fe->u.granted.cap_expire_at,
			fe->u.granted.budget_renew_at,
			fe->u.granted.tx_rate_kib_cycle,
			fe->u.granted.budget_byte,
			fe->u.granted.send_next_renewal_at,
			fe->u.granted.renewal_step_cycle,
			ip, __func__, rte_lcore_id());
		break;
	case GK_DECLINED:
		ret = snprintf(state_msg, sizeof(state_msg),
			"gk: log the flow state [state: GK_DECLINED (%hhu), flow hash value: %u, expire_at: %"PRIx64", grantor_ip: %s] in the flow table at %s with lcore %u",
			fe->state, fe->flow_hash_val, fe->u.declined.expire_at,
			ip, __func__, rte_lcore_id());
		break;
	case GK_BPF: {
		uint64_t *c = fe->u.bpf.cookie.mem;

		RTE_BUILD_BUG_ON(RTE_DIM(fe->u.bpf.cookie.mem) != 8);

		ret = snprintf(state_msg, sizeof(state_msg),
			"gk: log the flow state [state: GK_BPF (%hhu), flow hash value: %u, expire_at: 0x%"PRIx64", program_index=%u, cookie="
			"%016" PRIx64 ", %016" PRIx64 ", %016" PRIx64 ", %016" PRIx64
			", %016" PRIx64 ", %016" PRIx64 ", %016" PRIx64 ", %016" PRIx64 ", grantor_ip: %s] in the flow table at %s with lcore %u",
			fe->state, fe->flow_hash_val,
			fe->u.bpf.expire_at, fe->program_index,
			rte_cpu_to_be_64(c[0]), rte_cpu_to_be_64(c[1]),
			rte_cpu_to_be_64(c[2]), rte_cpu_to_be_64(c[3]),
			rte_cpu_to_be_64(c[4]), rte_cpu_to_be_64(c[5]),
			rte_cpu_to_be_64(c[6]), rte_cpu_to_be_64(c[7]),
			ip, __func__, rte_lcore_id());
		break;
	}
	default:
		ret = snprintf(state_msg, sizeof(state_msg),
			"gk: unknown flow with state %hhu and flow hash value %u in the flow table at %s with lcore %u, there is a bug in the GK block\n",
			fe->state, fe->flow_hash_val,
			__func__, rte_lcore_id());
		break;
	}

out:
	RTE_VERIFY(ret > 0 && ret < (int)sizeof(state_msg));
	print_flow_err_msg(&fe->flow, state_msg);
}

static void
log_flow_state(struct gk_log_flow *log, struct gk_instance *instance)
{
	struct flow_entry *fe;
	int ret = rte_hash_lookup_with_hash(instance->ip_flow_hash_table,
		&log->flow, log->flow_hash_val);
	if (ret < 0) {
		char err_msg[1024];

		ret = snprintf(err_msg, sizeof(err_msg),
			"gk: failed to log flow state at %s with lcore %u - flow doesn't exist\n",
			__func__, rte_lcore_id());

		RTE_VERIFY(ret > 0 && ret < (int)sizeof(err_msg));
		print_flow_err_msg(&log->flow, err_msg);
		return;
	}

	fe = &instance->ip_flow_entry_table[ret];
	print_flow_state(fe);
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
			if (fe->grantor_fib == fib)
				gk_del_flow_entry_from_hash(instance, fe);

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
process_gk_cmd(struct gk_cmd_entry *entry, struct gk_add_policy **policies,
	int *num_policies, struct gk_instance *instance)
{
	switch (entry->op) {
	case GK_ADD_POLICY_DECISION:
		policies[(*num_policies)++] = &entry->u.ggu;
		break;

	case GK_SYNCH_WITH_LPM:
		gk_synchronize(entry->u.fib, instance);
		break;

	case GK_FLUSH_FLOW_TABLE:
		flush_flow_table(&entry->u.flush.src,
			&entry->u.flush.dst, instance);
		break;

	case GK_LOG_FLOW_STATE:
		log_flow_state(&entry->u.log, instance);
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

/*
 * TODO A copy of this function is available in gk/co.c,
 * so drop it when possible.
 */
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

/*
 * TODO A copy of this function is available in gk/co.c,
 * so drop it when possible.
 */
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
 * TODO A copy of this function is available in gk/co.c,
 * so drop it when possible.
 */
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
lookup_fib_bulk(struct gk_lpm *ltbl, struct ip_flow **flows,
	int num_flows, struct gk_fib *fibs[])
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
		fibs[i] = look_up_fib(ltbl, flows[i]);
		if (fibs[i])
			rte_prefetch0(fibs[i]);
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

static void
process_fib(struct ipacket *packet, struct gk_fib *fib,
		uint16_t *num_tx, struct rte_mbuf **tx_bufs,
		struct acl_search *acl4, struct acl_search *acl6,
		uint16_t *num_pkts, struct rte_mbuf **icmp_bufs,
		struct gatekeeper_if *front, struct gatekeeper_if *back,
		struct gk_instance *instance) {
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
			return;
		}

		if (update_ip_hop_count(back, packet,
				num_pkts, icmp_bufs,
				&instance->back_icmp_rs,
				instance, drop_packet_back) < 0)
			return;

		tx_bufs[(*num_tx)++] = pkt;
		break;
	}

	case GK_FWD_NEIGHBOR_FRONT_NET: {
		/*
		 * The entry instructs to forward
		 * its packets to the neighbor in
		 * the front network, forward accordingly.
		 */
		if (packet->flow.proto == RTE_ETHER_TYPE_IPV4) {
			eth_cache = lookup_ether_cache(
				&fib->u.neigh,
				&packet->flow.f.v4.dst);
		} else {
			eth_cache = lookup_ether_cache(
				&fib->u.neigh6,
				&packet->flow.f.v6.dst);
		}

		RTE_VERIFY(eth_cache != NULL);

		if (adjust_pkt_len(pkt, front, 0) == NULL ||
				pkt_copy_cached_eth_header(pkt,
					eth_cache,
					front->l2_len_out)) {
			drop_packet(pkt);
			return;
		}

		if (update_ip_hop_count(back, packet,
				num_pkts, icmp_bufs,
				&instance->back_icmp_rs,
				instance, drop_packet_back) < 0)
			return;

		tx_bufs[(*num_tx)++] = pkt;
		break;
	}

	case GK_DROP:
		drop_packet(pkt);
		break;

	default:
		/* All other actions should log a warning. */
		GK_LOG(WARNING,
			"The fib entry has an unexpected action %u at %s\n",
			fib->action, __func__);
		drop_packet(pkt);
		break;
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

		process_fib(&pkt_arr[fidx], fibs[i],
			tx_front_num_pkts, tx_front_pkts, &acl4, &acl6,
			tx_back_num_pkts, tx_back_pkts, front, back,
			instance);
	}

	for (i = 0; i < num_lpm6_lookups; i++) {
		int fidx = lpm6_lookup_pos[i];

		process_fib(&pkt_arr[fidx], fibs6[i],
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
		fe->u.granted.cap_expire_at = now +
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
		fe->u.declined.expire_at = now +
			policy->params.declined.expire_sec * cycles_per_sec;
		break;

	case GK_BPF:
		fe->state = GK_BPF;
		fe->u.bpf.expire_at = now +
			policy->params.bpf.expire_sec * cycles_per_sec;
		fe->program_index = policy->params.bpf.program_index;
		fe->u.bpf.cookie = policy->params.bpf.cookie;
		break;

	default:
		GK_LOG(ERR, "Unknown flow state %u\n", policy->state);
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
	rte_memcpy(&fe->flow, &policy->flow, sizeof(fe->flow));
	fe->in_use = true;
	fe->grantor_fib = fib;

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

		ret = rte_hash_lookup_bulk_with_hash(
			instance->ip_flow_hash_table,
			(const void **)&flow_arr[done_lookups],
			&flow_hash_val_arr[done_lookups],
			num_keys, &pos_arr[done_lookups]);
		if (ret != 0) {
			GK_LOG(NOTICE,
				"failed to find multiple keys in the hash table at lcore %u\n",
				rte_lcore_id());
		}

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

static void
populate_front_tasks(struct gk_co_work *work,
	uint16_t port_front, uint16_t rx_queue_front)
{
	uint16_t front_max_pkt_burst = work->gk_conf->front_max_pkt_burst;
	struct rte_mbuf *rx_bufs[front_max_pkt_burst];
	/* Load a set of packets from the front NIC. */
	uint16_t num_rx = rte_eth_rx_burst(port_front, rx_queue_front, rx_bufs,
		front_max_pkt_burst);
	struct gk_measurement_metrics *stats;
	bool has_rss;
	int i;

	if (unlikely(num_rx == 0))
		return;

	stats = &work->instance->traffic_stats;
	stats->tot_pkts_num += num_rx;

	has_rss = work->gk_conf->net->front.rss;
	for (i = 0; i < num_rx; i++) {
		struct gk_co_task *task = &work->all_tasks[work->task_num++];
		struct rte_mbuf *pkt = rx_bufs[i];

		stats->tot_pkts_size += rte_pktmbuf_pkt_len(pkt);

		if (likely(has_rss)) {
			task->task_hash = pkt->hash.rss;
			task->task_arg = pkt;
			task->task_func = gk_co_process_front_pkt;
			schedule_task(work, task);
		} else {
			struct ipacket *packet = &work->packets[i];
			/*
			 * There is a chance that packets on the same flow
			 * are brought out of order. For example, consider that
			 * (1) three packets arrive on the following order:
			 * 	pkt1, pkt2, pkt3;
			 * (2) there are only two coroutines doing the work;
			 * (3) The packets are mapped to
			 * 	the coroutines as follow:
			 * 	* pkt1 and pkt2 goes coroutine 1,
			 * 	* pkt3 goes to coroutine 2;
			 * (4) Packets pkt2 and pkt3 belong to the same flow.
			 *
			 * Packet pkt1 and ptk3 are processed in parallel,
			 * receive their correct hashes, and are rescheduled.
			 * Once pk2 is recheduled, it is going to be placed
			 * after pk3 in the task queue of
			 * the assigned coroutine, that is, pk3 is going to
			 * be sent out before pkt2 (inverted order).
			 */
			task->task_hash = 0; /* Dummy hash. */
			/*
			 * Passing @packet instead of just @pkt so @packet
			 * can be carried over once the task is rescheduled.
			 */
			packet->pkt = pkt;
			task->task_arg = packet;
			task->task_func = gk_co_process_front_pkt_software_rss;
			schedule_task_to_any_co(work, task);
		}
	}
}

static void
add_cos_to_work(struct gk_co_work *work, struct gk_config *gk_conf,
	struct gk_instance *instance)
{
	unsigned int i;

	work->gk_conf = gk_conf;
	work->instance = instance;
	work->cos = instance->cos;
	work->co_max_num = gk_conf->co_max_num;
	work->co_num = RTE_MIN(2, work->co_max_num);
	work->front_ipv4_configured = ipv4_if_configured(&gk_conf->net->front);
	work->front_ipv6_configured = ipv6_if_configured(&gk_conf->net->front);

	RTE_VERIFY(work->co_num > 0);

	for (i = 0; i < work->co_max_num; i++)
		work->cos[i].work = work;
}

static void
update_cos(struct gk_co_work *work)
{
	/*
	 * The local variable @co_num is needed here to enable one to go
	 * above @work->co_max_num and below zero if needed.
	 */
	int32_t co_num = work->co_num;

	if (work->co_delta_num > 0) {
		/* @work->co_num is going up. */

		if (unlikely(co_num >= work->co_max_num)) {
			/*
			 * @work->co_num is at its maximum;
			 * Reverse direction.
			 */
			RTE_VERIFY(co_num == work->co_max_num);
			work->co_delta_num = - work->co_delta_num;
			work->co_num = RTE_MAX(1, co_num + work->co_delta_num);
			return;
		}

		work->co_num = RTE_MIN(work->co_max_num,
			co_num + work->co_delta_num);
		return;
	}

	/* @work->co_num is going down. */
	RTE_VERIFY(work->co_delta_num < 0);

	if (unlikely(co_num <= 1)) {
		/* @work->co_num is at its minimum; reverse direction. */
		RTE_VERIFY(co_num == 1);
		work->co_delta_num = - work->co_delta_num;
		work->co_num = RTE_MIN(work->co_max_num,
				co_num + work->co_delta_num);
		return;
	}

	work->co_num = RTE_MAX(1, co_num + work->co_delta_num);
}

static void
do_work(struct gk_co_work *work)
{
	uint16_t i, real_co_num = 0;
	uint64_t cycles;
	double avg_cycles_per_task;

	/* Add coroutines with tasks to @work->working_cos. */
	for (i = 0; i < work->co_num; i++) {
		struct gk_co *co = &work->cos[i];
		if (!list_empty(&co->task_queue)) {
			list_add_tail(&co->co_list, &work->working_cos);
			real_co_num++;
		}
	}

	/* Is there any work to do? */
	if (unlikely(list_empty(&work->working_cos))) {
		RTE_VERIFY(real_co_num == 0);
		RTE_VERIFY(work->task_num == 0);
		return;
	}
	RTE_VERIFY(real_co_num > 0);
	RTE_VERIFY(work->task_num > 0);

	/* Do work. */
	cycles = rte_rdtsc();
	coro_transfer(&work->instance->coro_root,
		&list_first_entry(&work->working_cos, struct gk_co, co_list)->
		coro);
	cycles = rte_rdtsc() - cycles;
	avg_cycles_per_task = (double)cycles / work->task_num;

	if (work->co_num != real_co_num) {
		/* Workload changed; adjust quickly. */
		RTE_VERIFY(work->co_num > real_co_num);
		work->co_prv_num = real_co_num;
		work->avg_cycles_per_task = avg_cycles_per_task;
		work->co_num = real_co_num;
		return update_cos(work);
	}

	if (work->co_prv_num == 0) {
		/* Initialize the performance tracking fields. */
		work->co_prv_num = real_co_num;
		work->avg_cycles_per_task = avg_cycles_per_task;
		return update_cos(work);
	}

	if (avg_cycles_per_task >= work->avg_cycles_per_task) {
		/* The last change did not bring an improvement; go back. */
		work->co_num = work->co_prv_num;
		/* Reset measurement. */
		work->co_prv_num = 0;
		/* Change adjustment direction. */
		work->co_delta_num = - work->co_delta_num;
		return;
	}

	/* @real_co_num is an improvement. */
	work->co_prv_num = real_co_num;
	work->avg_cycles_per_task = avg_cycles_per_task;
	update_cos(work);
}

static void
flush_work(struct gk_co_work *work,
	uint16_t port_front, uint16_t tx_queue_front,
	uint16_t port_back, uint16_t tx_queue_back,
	unsigned int lcore)
{
	struct gk_instance *instance = work->instance;

	uint16_t front_max_pkt_burst = work->gk_conf->front_max_pkt_burst;
	uint16_t back_max_pkt_burst = work->gk_conf->back_max_pkt_burst;
	uint32_t max_pkt_burst = front_max_pkt_burst + back_max_pkt_burst;
	struct gatekeeper_if *front = &work->gk_conf->net->front;

	/*
	 * Flush packets.
	 */

	send_pkts(port_front, tx_queue_front,
		work->tx_front_num_pkts, work->tx_front_pkts);
	RTE_VERIFY(work->tx_front_num_pkts <= max_pkt_burst);
	work->tx_front_num_pkts = 0;

	send_pkts(port_back, tx_queue_back,
		work->tx_back_num_pkts, work->tx_back_pkts);
	RTE_VERIFY(work->tx_back_num_pkts <= max_pkt_burst);
	work->tx_back_num_pkts = 0;

	/*
	 * Flush front.
	 */

	if (work->front_num_req > 0) {
		uint16_t num_req = work->front_num_req;
		uint64_t acc_size_request[num_req + 1];
		struct gk_measurement_metrics *stats = &instance->traffic_stats;
		int i, ret;

		/*
		 * The byte length of the packets must be computed before
		 * calling gk_solicitor_enqueue_bulk() because after it
		 * the GK block no longer owns the packets.
		 */
		acc_size_request[0] = 0;
		for (i = 1; i <= num_req; i++) {
			acc_size_request[i] = acc_size_request[i - 1] +
				rte_pktmbuf_pkt_len(
					work->front_req_bufs[i - 1]
				);
		}

		ret = RTE_MAX(
			gk_solicitor_enqueue_bulk(work->gk_conf->sol_conf,
				work->front_req_bufs, num_req),
			0);

		stats->pkts_num_request += ret;
		stats->pkts_size_request += acc_size_request[ret];

		for (i = ret; i < num_req; i++)
			drop_packet_front(work->front_req_bufs[i], instance);

		RTE_VERIFY(num_req <= front_max_pkt_burst);
		work->front_num_req = 0;
	}

	if (work->front_num_arp > 0) {
		submit_arp(work->front_arp_bufs, work->front_num_arp, front);
		RTE_VERIFY(work->front_num_arp <= front_max_pkt_burst);
		work->front_num_arp = 0;
	}

	RTE_VERIFY(work->front_acl4.num <= front_max_pkt_burst);
	RTE_VERIFY(work->front_acl6.num <= front_max_pkt_burst);
	process_pkts_acl(front, lcore, &work->front_acl4, RTE_ETHER_TYPE_IPV4);
	process_pkts_acl(front, lcore, &work->front_acl6, RTE_ETHER_TYPE_IPV6);

	/*
	 * TODO Flush back.
	 */

	/*
	 * Update flow table.
	 */

	if (work->del_fe != NULL) {
		RTE_VERIFY(work->del_fe->in_use);
		/*
		 * Test that the flow entry is expired once more because
		 * it may have been update since it tested as expired and
		 * arriving here.
		 */
		if (likely(is_flow_expired(work->del_fe, rte_rdtsc())))
			gk_del_flow_entry_from_hash(instance, work->del_fe);
		work->del_fe = NULL;
	}

	/*
	 * Adding new entries to the flow table should be among the last steps
	 * to do because when the flow table is full,
	 * rte_hash_cuckoo_make_space_mw() is going to be called. And
	 * this function disrupts the cache of the running core.
	 * rte_hash_cuckoo_make_space_mw() may access up to 1000 buckets and,
	 * on 64-bit platforms, consumes about 32KB of execution stack.
	 */
	if (work->temp_fes_num > 0) {
		unsigned int i;
		for (i = 0; i < work->temp_fes_num; i++) {
			struct flow_entry *temp_fe = &work->temp_fes[i];
			struct flow_entry *fe;
			int ret = gk_hash_add_flow_entry(instance,
				&temp_fe->flow, temp_fe->flow_hash_val,
				work->gk_conf);
			if (ret == -ENOSPC) {
				/* Flow table is full. */
				break;
			}
			if (unlikely(ret < 0)) {
				GK_LOG(ERR,
					"Failed to add an flow entry ret=%i\n",
					ret);
				continue;
			}
			fe = &instance->ip_flow_entry_table[ret];
			rte_memcpy(fe, temp_fe, sizeof(*fe));
		}
		RTE_VERIFY(work->temp_fes_num <= (front_max_pkt_burst +
			work->gk_conf->mailbox_burst_size));
		work->temp_fes_num = 0;
	}

	/*
	 * Reset fields of @work.
	 */

	RTE_VERIFY(work->task_num <= work->task_total);
	work->task_num = 0;
	work->any_co_index = 0;
	memset(work->leftover, 0,
		sizeof(*work->leftover) * (work->leftover_mask + 1));
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

	uint32_t entry_idx = 0;
	uint64_t last_measure_tsc = rte_rdtsc();
	uint64_t basic_measurement_logging_cycles =
		gk_conf->basic_measurement_logging_ms *
		rte_get_tsc_hz() / 1000;
	uint32_t scan_iter = gk_conf->flow_table_scan_iter;
	uint32_t iter_count = 0;

	DEFINE_GK_CO_WORK(work, gk_conf->front_max_pkt_burst,
		gk_conf->back_max_pkt_burst, gk_conf->mailbox_burst_size,
		/*
		 * The 4* is intended to minimize collisions, whereas the -1 is
		 * intended to avoid doubling the size when
		 * the expression already is a power of 2.
		 */
		rte_combine32ms1b(4 * (gk_conf->front_max_pkt_burst +
			gk_conf->mailbox_burst_size) - 1),
		1 /* One extra tast for the full scanning of the flow table. */
	);

	GK_LOG(NOTICE, "The GK block is running at lcore = %u\n", lcore);

	gk_conf_hold(gk_conf);
	add_cos_to_work(&work, gk_conf, instance);

	while (likely(!exiting)) {

		populate_front_tasks(&work, port_front, rx_queue_front);

		/*
		 * Have the expiration test after all flow-ralated work to
		 * give one more chance for entries to not expire.
		 */
		if (iter_count >= scan_iter) {
			struct gk_co_task *task =
				&work.all_tasks[work.task_num++];
			entry_idx = (entry_idx + 1) % gk_conf->flow_ht_size;

			task->task_hash = 0; /* Dummy hash. */
			task->task_arg =
				&instance->ip_flow_entry_table[entry_idx];
			task->task_func = gk_co_scan_flow_table;
			schedule_task_to_any_co(&work, task);

			iter_count = 0;
		} else
			iter_count++;

		do_work(&work);

		process_pkts_back(port_back, rx_queue_back, lcore,
			&work.tx_front_num_pkts, work.tx_front_pkts,
			&work.tx_back_num_pkts,  work.tx_back_pkts,
			instance, gk_conf);

		flush_work(&work, port_front, tx_queue_front,
			port_back, tx_queue_back, lcore);

		process_cmds_from_mailbox(instance, gk_conf);

		if (rte_rdtsc() - last_measure_tsc >=
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

		destroy_mailbox(&gk_conf->instances[i].mb);
		free_cos(gk_conf->instances[i].cos, gk_conf->co_max_num);
		coro_destroy(&gk_conf->instances[i].coro_root);
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

	if (gk_conf->co_max_num == 0) {
		GK_LOG(ERR, "There must be at least one coroutine\n");
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
		GK_LOG(ERR, "gk: failed to log flow state - source address is NULL\n");
		return -1;
	}
	if (dst_addr == NULL) {
		GK_LOG(ERR, "gk: failed to log flow state - destination address is NULL\n");
		return -1;
	}
	if (gk_conf == NULL) {
		GK_LOG(ERR, "gk: failed to log flow state - gk_conf is NULL\n");
		return -1;
	}

	ret = convert_str_to_ip(src_addr, &src);
	if (ret < 0) {
		GK_LOG(ERR, "gk: failed to log flow state - source address (%s) is invalid\n",
			src_addr);
		return -1;
	}

	ret = convert_str_to_ip(dst_addr, &dst);
	if (ret < 0) {
		GK_LOG(ERR, "gk: failed to log flow state - destination address (%s) is invalid\n",
			dst_addr);
		return -1;
	}

	if (unlikely(src.proto != dst.proto)) {
		GK_LOG(ERR, "gk: failed to log flow state - source (%s) and destination (%s) addresses don't have the same IP type\n",
			src_addr, dst_addr);
		return -1;
	}

	if (unlikely(src.proto != RTE_ETHER_TYPE_IPV4 && src.proto !=
			RTE_ETHER_TYPE_IPV6)) {
		GK_LOG(ERR, "gk: failed to log flow state - source (%s) and destination (%s) addresses don't have valid IP type %hu\n",
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
		GK_LOG(ERR, "gk: failed to get responsible GK mailbox to log flow state that matches src_addr=%s and dst_addr=%s\n",
			src_addr, dst_addr);
		return -1;
	}

	entry = mb_alloc_entry(mb);
	if (entry == NULL) {
		GK_LOG(WARNING,
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
