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

#include <stdbool.h>
#include <arpa/inet.h>
#include <lualib.h>
#include <lauxlib.h>
#include <netinet/ip.h>
#include <math.h>

#include <rte_log.h>
#include <rte_ether.h>
#include <rte_lcore.h>
#include <rte_malloc.h>
#include <rte_random.h>
#include <rte_cycles.h>
#include <rte_common.h>
#include <rte_byteorder.h>

#include "gatekeeper_fib.h"
#include "gatekeeper_lls.h"
#include "gatekeeper_acl.h"
#include "gatekeeper_ggu.h"
#include "gatekeeper_ipip.h"
#include "gatekeeper_gk.h"
#include "gatekeeper_gt.h"
#include "gatekeeper_main.h"
#include "gatekeeper_net.h"
#include "gatekeeper_launch.h"
#include "gatekeeper_l2.h"
#include "gatekeeper_varip.h"
#include "lua_lpm.h"
#include "luajit-ffi-cdata.h"

int gt_logtype;

#define GT_LOG(level, ...)                               \
	rte_log_ratelimit(RTE_LOG_ ## level, gt_logtype, \
		"GATEKEEPER GT: " __VA_ARGS__)

static int
get_block_idx(struct gt_config *gt_conf, unsigned int lcore_id)
{
	int i;
	for (i = 0; i < gt_conf->num_lcores; i++)
		if (gt_conf->lcores[i] == lcore_id)
			return i;
	rte_panic("Unexpected condition: lcore %u is not running a gt block\n",
		lcore_id);
	return 0;
}

static int
gt_setup_rss(struct gt_config *gt_conf)
{
	int i;
	uint16_t port_in = gt_conf->net->front.id;
	uint16_t gt_queues[gt_conf->num_lcores];

	for (i = 0; i < gt_conf->num_lcores; i++)
		gt_queues[i] = gt_conf->instances[i].rx_queue;

	return gatekeeper_setup_rss(port_in, gt_queues, gt_conf->num_lcores);
}

static int
gt_parse_incoming_pkt(struct rte_mbuf *pkt, struct gt_packet_headers *info)
{
	uint8_t inner_ip_ver;
	uint16_t parsed_len;
	int outer_ipv6_hdr_len = 0;
	struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(pkt,
		struct rte_ether_hdr *);
	struct rte_ipv4_hdr *outer_ipv4_hdr = NULL;
	struct rte_ipv6_hdr *outer_ipv6_hdr = NULL;
	struct rte_ipv4_hdr *inner_ipv4_hdr = NULL;
	struct rte_ipv6_hdr *inner_ipv6_hdr = NULL;

	info->frag = false;
	info->l2_hdr = eth_hdr;
	info->outer_ethertype = rte_be_to_cpu_16(pkt_in_skip_l2(pkt, eth_hdr,
		&info->outer_l3_hdr));
	parsed_len = pkt_in_l2_hdr_len(pkt);

	switch (info->outer_ethertype) {
	case RTE_ETHER_TYPE_IPV4:
		if (pkt->data_len < parsed_len + sizeof(struct rte_ipv4_hdr))
			return -1;

		outer_ipv4_hdr = (struct rte_ipv4_hdr *)info->outer_l3_hdr;

		if (outer_ipv4_hdr->next_proto_id != IPPROTO_IPIP)
			return -1;

		parsed_len += ipv4_hdr_len(outer_ipv4_hdr);
		info->priority = (outer_ipv4_hdr->type_of_service >> 2);
		info->outer_ecn =
			outer_ipv4_hdr->type_of_service & IPTOS_ECN_MASK;
		break;
	case RTE_ETHER_TYPE_IPV6: {
		uint32_t vtc_flow;
		uint8_t encapsulated_proto;

		if (pkt->data_len < parsed_len + sizeof(struct rte_ipv6_hdr))
			return -1;

		outer_ipv6_hdr = (struct rte_ipv6_hdr *)info->outer_l3_hdr;
		outer_ipv6_hdr_len = ipv6_skip_exthdr(outer_ipv6_hdr,
			pkt->data_len - parsed_len, &encapsulated_proto);
		if (outer_ipv6_hdr_len < 0) {
			GT_LOG(ERR,
				"Failed to parse the packet's outer IPv6 extension headers\n");
			return -1;
		}

		if (encapsulated_proto != IPPROTO_IPV6)
			return -1;

		parsed_len += outer_ipv6_hdr_len;
		vtc_flow = rte_be_to_cpu_32(outer_ipv6_hdr->vtc_flow);
		info->priority = ((vtc_flow >> 20) & 0xFF) >> 2;
		info->outer_ecn = (vtc_flow >> 20) & IPTOS_ECN_MASK;
		break;
	}
	default:
		return -1;
	}

	if (pkt->data_len < parsed_len + sizeof(struct rte_ipv4_hdr))
		return -1;

	if (outer_ipv4_hdr != NULL) {
		inner_ipv4_hdr =
			(struct rte_ipv4_hdr *)ipv4_skip_exthdr(outer_ipv4_hdr);
	} else {
		inner_ipv4_hdr = (struct rte_ipv4_hdr *)(
			(uint8_t *)outer_ipv6_hdr + outer_ipv6_hdr_len);
	}

 	inner_ip_ver = (inner_ipv4_hdr->version_ihl & 0xF0) >> 4;
	info->inner_l3_hdr = inner_ipv4_hdr;

	if (inner_ip_ver == 4) {
		info->inner_ip_ver = RTE_ETHER_TYPE_IPV4;
		info->l4_proto = inner_ipv4_hdr->next_proto_id;
		info->l4_hdr = ipv4_skip_exthdr(inner_ipv4_hdr);

		if (rte_ipv4_frag_pkt_is_fragmented(inner_ipv4_hdr)) {
			info->frag = true;
			info->l2_outer_l3_len = parsed_len;
			info->inner_l3_len = ipv4_hdr_len(inner_ipv4_hdr);
			info->frag_hdr = NULL;
		}

		parsed_len += ipv4_hdr_len(inner_ipv4_hdr);
	} else if (likely(inner_ip_ver == 6)) {
		int inner_ipv6_len;

		if (pkt->data_len < parsed_len + sizeof(struct rte_ipv6_hdr))
			return -1;

		inner_ipv6_hdr = (struct rte_ipv6_hdr *)info->inner_l3_hdr;
		inner_ipv6_len = ipv6_skip_exthdr(inner_ipv6_hdr,
			pkt->data_len - parsed_len, &info->l4_proto);
		if (inner_ipv6_len < 0) {
			GT_LOG(ERR,
				"Failed to parse the packet's inner IPv6 extension headers\n");
			return -1;
		}

		info->inner_ip_ver = RTE_ETHER_TYPE_IPV6;
		info->l4_hdr = (uint8_t *)inner_ipv6_hdr + inner_ipv6_len;
		info->frag_hdr =
			rte_ipv6_frag_get_ipv6_fragment_header(inner_ipv6_hdr);

		if (info->frag_hdr != NULL) {
			info->frag = true;
			info->l2_outer_l3_len = parsed_len;
			info->inner_l3_len = inner_ipv6_len;
		}

		parsed_len += inner_ipv6_len;
	} else
		return -1;

	info->upper_len = pkt->data_len - parsed_len;
	return 0;
}

static struct rte_mbuf *
gt_reassemble_incoming_pkt(struct rte_mbuf *pkt,
	uint64_t tms, struct gt_packet_headers *info,
	struct rte_ip_frag_death_row *death_row, struct gt_instance *instance)
{
	/* Prepare mbuf: setup l2_len/l3_len. */
	pkt->l2_len = info->l2_outer_l3_len;
	pkt->l3_len = info->inner_l3_len;

	if (info->inner_ip_ver == RTE_ETHER_TYPE_IPV4) {
		/* Process this IPv4 fragment. */
		return rte_ipv4_frag_reassemble_packet(
			instance->frag_tbl, death_row,
			pkt, tms, info->inner_l3_hdr);
	}

	if (likely(info->inner_ip_ver == RTE_ETHER_TYPE_IPV6)) {
		/* Process this IPv6 fragment. */
		return rte_ipv6_frag_reassemble_packet(
			instance->frag_tbl, death_row,
			pkt, tms, info->inner_l3_hdr, info->frag_hdr);
	}

	rte_panic("Unexpected condition: gt at lcore %u reassembles a packet with unknown IP version %hu\n",
		rte_lcore_id(), info->inner_ip_ver);

	return NULL;
}

#define CTYPE_STRUCT_GT_PACKET_HEADERS_PTR "struct gt_packet_headers *"
#define CTYPE_STRUCT_GGU_POLICY_PTR "struct ggu_policy *"

static int
lookup_policy_decision(struct gt_packet_headers *pkt_info,
	struct ggu_policy *policy, struct gt_instance *instance)
{
	void *gt_pkt_hdr_cdata;
	void *ggu_policy_cdata;
	uint32_t correct_ctypeid_gt_packet_headers = luaL_get_ctypeid(
		instance->lua_state, CTYPE_STRUCT_GT_PACKET_HEADERS_PTR);
	uint32_t correct_ctypeid_ggu_policy = luaL_get_ctypeid(
		instance->lua_state, CTYPE_STRUCT_GGU_POLICY_PTR);
	int ret;

	policy->flow.proto = pkt_info->inner_ip_ver;
	if (pkt_info->inner_ip_ver == RTE_ETHER_TYPE_IPV4) {
		struct rte_ipv4_hdr *ip4_hdr = pkt_info->inner_l3_hdr;

		policy->flow.f.v4.src.s_addr = ip4_hdr->src_addr;
		policy->flow.f.v4.dst.s_addr = ip4_hdr->dst_addr;
	} else if (likely(pkt_info->inner_ip_ver == RTE_ETHER_TYPE_IPV6)) {
		struct rte_ipv6_hdr *ip6_hdr = pkt_info->inner_l3_hdr;

		rte_memcpy(policy->flow.f.v6.src.s6_addr, ip6_hdr->src_addr,
			sizeof(policy->flow.f.v6.src.s6_addr));
		rte_memcpy(policy->flow.f.v6.dst.s6_addr, ip6_hdr->dst_addr,
			sizeof(policy->flow.f.v6.dst.s6_addr));
	} else {
		GT_LOG(ERR,
			"Unexpected condition: GT block at lcore %u lookups policy decision for an non-IP packet in function %s\n",
			rte_lcore_id(), __func__);
		return -1;
	}

	lua_getglobal(instance->lua_state, "lookup_policy");
	gt_pkt_hdr_cdata = luaL_pushcdata(instance->lua_state,
		correct_ctypeid_gt_packet_headers,
		sizeof(struct gt_packet_headers *));
	*(struct gt_packet_headers **)gt_pkt_hdr_cdata = pkt_info;
	ggu_policy_cdata = luaL_pushcdata(instance->lua_state,
		correct_ctypeid_ggu_policy, sizeof(struct ggu_policy *));
	*(struct ggu_policy **)ggu_policy_cdata = policy;

	if (lua_pcall(instance->lua_state, 2, 1, 0) != 0) {
		GT_LOG(ERR,
			"Error running function `lookup_policy': %s, at lcore %u\n",
			lua_tostring(instance->lua_state, -1), rte_lcore_id());
		return -1;
	}

	ret = lua_toboolean(instance->lua_state, -1);
	lua_settop(instance->lua_state, 0);
	return ret;
}

static int
lookup_frag_punish_policy_decision(struct gt_packet_headers *pkt_info,
	struct ggu_policy *policy, struct gt_instance *instance)
{
	void *ggu_policy_cdata;
	uint32_t correct_ctypeid_ggu_policy = luaL_get_ctypeid(
		instance->lua_state, CTYPE_STRUCT_GGU_POLICY_PTR);

	policy->flow.proto = pkt_info->inner_ip_ver;
	if (pkt_info->inner_ip_ver == RTE_ETHER_TYPE_IPV4) {
		struct rte_ipv4_hdr *ip4_hdr = pkt_info->inner_l3_hdr;

		policy->flow.f.v4.src.s_addr = ip4_hdr->src_addr;
		policy->flow.f.v4.dst.s_addr = ip4_hdr->dst_addr;
	} else if (likely(pkt_info->inner_ip_ver == RTE_ETHER_TYPE_IPV6)) {
		struct rte_ipv6_hdr *ip6_hdr = pkt_info->inner_l3_hdr;

		rte_memcpy(policy->flow.f.v6.src.s6_addr, ip6_hdr->src_addr,
			sizeof(policy->flow.f.v6.src.s6_addr));
		rte_memcpy(policy->flow.f.v6.dst.s6_addr, ip6_hdr->dst_addr,
			sizeof(policy->flow.f.v6.dst.s6_addr));
	} else {
		GT_LOG(ERR,
			"Unexpected condition: GT block at lcore %u lookups policy decision for an non-IP packet in function %s\n",
			rte_lcore_id(), __func__);
		return -1;
	}

	lua_getglobal(instance->lua_state, "lookup_frag_punish_policy");
	ggu_policy_cdata = luaL_pushcdata(instance->lua_state,
		correct_ctypeid_ggu_policy, sizeof(struct ggu_policy *));
	*(struct ggu_policy **)ggu_policy_cdata = policy;

	if (lua_pcall(instance->lua_state, 1, 0, 0) != 0) {
		GT_LOG(ERR,
			"Error running function `lookup_frag_punish_policy': %s, at lcore %u\n",
			lua_tostring(instance->lua_state, -1), rte_lcore_id());
		return -1;
	}

	return 0;
}

static inline bool
is_valid_dest_addr(struct gt_config *gt_conf,
	struct gt_packet_headers *pkt_info)
{
	return (pkt_info->outer_ethertype == RTE_ETHER_TYPE_IPV4 &&
			((struct rte_ipv4_hdr *)
			pkt_info->outer_l3_hdr)->dst_addr
			== gt_conf->net->front.ip4_addr.s_addr)
			||
			(pkt_info->outer_ethertype == RTE_ETHER_TYPE_IPV6 &&
			memcmp(((struct rte_ipv6_hdr *)
			pkt_info->outer_l3_hdr)->dst_addr,
			gt_conf->net->front.ip6_addr.s6_addr,
			sizeof(gt_conf->net->front.ip6_addr)) == 0);
}

static void
print_ip_err_msg(struct gt_packet_headers *pkt_info)
{
	char src[128];
	char dst[128];

	if (pkt_info->outer_ethertype == RTE_ETHER_TYPE_IPV4) {
		if (inet_ntop(AF_INET, &((struct rte_ipv4_hdr *)
				pkt_info->outer_l3_hdr)->src_addr,
				src, sizeof(src)) == NULL) {
			GT_LOG(ERR, "%s: failed to convert a number to an IPv4 address (%s)\n",
				__func__, strerror(errno));
			return;
		}

		if (inet_ntop(AF_INET, &((struct rte_ipv4_hdr *)
				pkt_info->outer_l3_hdr)->dst_addr,
				dst, sizeof(dst)) == NULL) {
			GT_LOG(ERR, "%s: failed to convert a number to an IPv4 address (%s)\n",
				__func__, strerror(errno));
			return;
		}
	} else {
		if (inet_ntop(AF_INET6, &((struct rte_ipv6_hdr *)
				pkt_info->outer_l3_hdr)->src_addr,
				src, sizeof(src)) == NULL) {
			GT_LOG(ERR, "%s: failed to convert a number to an IPv6 address (%s)\n",
				__func__, strerror(errno));
			return;
		}

		if (inet_ntop(AF_INET6, &((struct rte_ipv6_hdr *)
				pkt_info->outer_l3_hdr)->dst_addr,
				dst, sizeof(dst)) == NULL) {
			GT_LOG(ERR, "%s: failed to convert a number to an IPv6 address (%s)\n",
				__func__, strerror(errno));
			return;
		}
	}

	GT_LOG(ALERT,
		"Receiving a packet with IP source address %s, and destination address %s, whose destination IP address is not the Grantor server itself\n",
		src, dst);
}

static void
gt_arp_and_nd_req_cb(const struct lls_map *map, void *arg,
	__attribute__((unused))enum lls_reply_ty ty, int *pcall_again)
{
	struct ether_cache *eth_cache = arg;

	if (pcall_again == NULL) {
		clear_ether_cache(eth_cache);
		return;
	}

	/*
	 * Deal with concurrency control by sequential lock
	 * on the nexthop entry.
	 */
	write_seqlock(&eth_cache->lock);
	rte_ether_addr_copy(&map->ha, &eth_cache->l2_hdr.eth_hdr.d_addr);
	eth_cache->stale = map->stale;
	write_sequnlock(&eth_cache->lock);

	*pcall_again = true;
}

/*
 * Fill up the Ethernet cached header.
 * Note that the destination MAC address should be filled up by LLS.
 */
static int
gt_fill_up_ether_cache_locked(struct ether_cache *eth_cache,
	uint16_t inner_ip_ver, void *ip_dst, struct gatekeeper_if *iface)
{
	int ret;
	unsigned lcore_id = rte_lcore_id();

	eth_cache->stale = true;
	eth_cache->ip_addr.proto = inner_ip_ver;

	if (inner_ip_ver == RTE_ETHER_TYPE_IPV4) {
		rte_memcpy(&eth_cache->ip_addr.ip.v4,
			ip_dst, sizeof(eth_cache->ip_addr.ip.v4));
	} else {
		rte_memcpy(&eth_cache->ip_addr.ip.v6,
			ip_dst, sizeof(eth_cache->ip_addr.ip.v6));
	}

	if (iface->vlan_insert) {
		fill_vlan_hdr(&eth_cache->l2_hdr.eth_hdr,
			iface->vlan_tag_be, inner_ip_ver);
	} else {
		eth_cache->l2_hdr.eth_hdr.ether_type =
			rte_cpu_to_be_16(inner_ip_ver);
	}

	rte_ether_addr_copy(&iface->eth_addr,
		&eth_cache->l2_hdr.eth_hdr.s_addr);
	rte_atomic32_set(&eth_cache->ref_cnt, 1);

	if (inner_ip_ver == RTE_ETHER_TYPE_IPV4) {
		ret = hold_arp(gt_arp_and_nd_req_cb,
			eth_cache, ip_dst, lcore_id);
	} else {
		ret = hold_nd(gt_arp_and_nd_req_cb,
			eth_cache, ip_dst, lcore_id);
	}

	if (ret < 0)
		clear_ether_cache(eth_cache);

	return ret;
}

static int
drop_cache_entry_randomly(struct neighbor_hash_table *neigh, uint16_t ip_ver)
{
	int ret;
	uint32_t entry_id = rte_rand() % neigh->tbl_size;
	struct ether_cache *eth_cache;
	uint32_t entry_start_idx = entry_id;

	while (true) {
		eth_cache = &neigh->cache_tbl[entry_id];
		if (rte_atomic32_read(&eth_cache->ref_cnt) == 0) {
			entry_id = (entry_id + 1) % neigh->tbl_size;
			eth_cache = NULL;
		} else
			break;

		if (entry_start_idx == entry_id)
			break;
	}

	if (eth_cache == NULL)
		return -1;

	if (ip_ver == RTE_ETHER_TYPE_IPV4) {
		ret = put_arp(&eth_cache->ip_addr.ip.v4, rte_lcore_id());
		if (ret < 0)
			return ret;

		ret = rte_hash_del_key(neigh->hash_table,
			&eth_cache->ip_addr.ip.v4);
		if (ret < 0) {
			GT_LOG(CRIT,
				"Failed to delete an Ethernet cache entry from the IPv4 neighbor table at %s, we are not trying to recover from this failure\n",
				__func__);
		}
		return ret;
	}

	if (likely(ip_ver == RTE_ETHER_TYPE_IPV6)) {
		ret = put_nd(&eth_cache->ip_addr.ip.v6, rte_lcore_id());
		if (ret < 0)
			return ret;

		ret = rte_hash_del_key(neigh->hash_table,
			&eth_cache->ip_addr.ip.v6);
		if (ret < 0) {
			GT_LOG(CRIT,
				"Failed to delete an Ethernet cache entry from the IPv6 neighbor table at %s, we are not trying to recover from this failure\n",
				__func__);
		}
		return ret;
	}

	return -1;
}

static struct ether_cache *
get_new_ether_cache(struct neighbor_hash_table *neigh)
{
	int i;
	for (i = 0; i < neigh->tbl_size; i++) {
		if (rte_atomic32_read(&neigh->cache_tbl[i].ref_cnt) == 0)
			return &neigh->cache_tbl[i];
	}

	return NULL;
}

static struct ether_cache *
gt_neigh_get_ether_cache(struct neighbor_hash_table *neigh,
	uint16_t inner_ip_ver, void *ip_dst, struct gatekeeper_if *iface)
{
	int ret;
	struct ether_cache *eth_cache = lookup_ether_cache(neigh, ip_dst);
	if (eth_cache != NULL)
		return eth_cache;

	eth_cache = get_new_ether_cache(neigh);
	if (eth_cache == NULL) {
		ret = drop_cache_entry_randomly(neigh, inner_ip_ver);
		if (ret < 0)
			return NULL;

		eth_cache = get_new_ether_cache(neigh);
		if (eth_cache == NULL) {
			GT_LOG(WARNING,
				"Failed to get a new Ethernet cache entry from the neighbor hash table at %s, the cache is overflowing\n",
				__func__);
			return NULL;
		}
	}

	ret = gt_fill_up_ether_cache_locked(
		eth_cache, inner_ip_ver, ip_dst, iface);
	if (ret < 0)
		return NULL;

	ret = rte_hash_add_key_data(neigh->hash_table, ip_dst, eth_cache);
	if (ret == 0)
		return eth_cache;

	GT_LOG(ERR,
		"Failed to add a cache entry to the neighbor hash table at %s\n",
		__func__);

	if (inner_ip_ver == RTE_ETHER_TYPE_IPV4)
		put_arp(ip_dst, rte_lcore_id());
	else
		put_nd(ip_dst, rte_lcore_id());

	/*
	 * By calling put_xxx(), the LLS block will call
	 * gt_arp_and_nd_req_cb(), which, in turn, will call
	 * clear_ether_cache(), so we can return directly here.
	 */
	return NULL;
}

static int
decap_and_fill_eth(struct rte_mbuf *m, struct gt_config *gt_conf,
	struct gt_packet_headers *pkt_info, struct gt_instance *instance)
{
	struct neighbor_hash_table *neigh;
	struct ether_cache *eth_cache;
	void *ip_dst;
	bool is_neighbor;
	int bytes_to_add;
	struct gatekeeper_if *iface = &gt_conf->net->front;

	if (pkt_info->inner_ip_ver == RTE_ETHER_TYPE_IPV4) {
		/*
		 * The Full-functionality Option for setting ECN bits in
		 * IP-in-IP packets. RFC 3168, section 9.1.1.
		 *
		 * If the outer header's ECN codepoint is CE and the inner
		 * header's ECN codepoint is not CE, set it and clear the
		 * checksum so that hardware can recompute it.
		 */
		struct rte_ipv4_hdr *inner_ipv4_hdr = pkt_info->inner_l3_hdr;
		if (((inner_ipv4_hdr->type_of_service & IPTOS_ECN_MASK) !=
				IPTOS_ECN_CE) &&
				(pkt_info->outer_ecn == IPTOS_ECN_CE)) {
			inner_ipv4_hdr->type_of_service |= IPTOS_ECN_CE;
			m->l3_len = ipv4_hdr_len(inner_ipv4_hdr);
			set_ipv4_checksum(iface, m, inner_ipv4_hdr);
		}

		neigh = &instance->neigh;
		ip_dst = &inner_ipv4_hdr->dst_addr;

		is_neighbor = ip4_same_subnet(iface->ip4_addr.s_addr,
			*(uint32_t *)ip_dst, iface->ip4_mask.s_addr);
	} else if (likely(pkt_info->inner_ip_ver == RTE_ETHER_TYPE_IPV6)) {
		/*
		 * Since there's no checksum in the IPv6 header, skip the
		 * extra comparisons and set the ECN bits if needed
		 * (even if it's redundant).
		 */
		struct rte_ipv6_hdr *inner_ipv6_hdr = pkt_info->inner_l3_hdr;
		if (pkt_info->outer_ecn == IPTOS_ECN_CE)
			inner_ipv6_hdr->vtc_flow |=
				rte_cpu_to_be_32(IPTOS_ECN_CE << 20);

		neigh = &instance->neigh6;
		ip_dst = inner_ipv6_hdr->dst_addr;

		is_neighbor = ip6_same_subnet(&iface->ip6_addr, ip_dst,
			&iface->ip6_mask);
	} else
		return -1;

	bytes_to_add = pkt_info->outer_ethertype == RTE_ETHER_TYPE_IPV4
		? -sizeof(struct rte_ipv4_hdr)
		: -sizeof(struct rte_ipv6_hdr);

	if (adjust_pkt_len(m, iface, bytes_to_add) == NULL) {
		GT_LOG(ERR, "Could not adjust packet length\n");
		return -1;
	}

	if (!is_neighbor) {
		struct rte_ether_hdr *eth_hdr =
			rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
		struct rte_ether_hdr *raw_eth = pkt_info->l2_hdr;

		rte_ether_addr_copy(&raw_eth->s_addr, &eth_hdr->d_addr);
		rte_ether_addr_copy(&raw_eth->d_addr, &eth_hdr->s_addr);
		m->l2_len = iface->l2_len_out;

		if (iface->vlan_insert) {
			fill_vlan_hdr(eth_hdr, iface->vlan_tag_be,
				pkt_info->inner_ip_ver);
		} else {
			eth_hdr->ether_type =
				rte_cpu_to_be_16(pkt_info->inner_ip_ver);
		}

		return 0;
	}

	/*
	 * The destination MAC address comes from LLS block.
	 */
	eth_cache = gt_neigh_get_ether_cache(neigh,
		pkt_info->inner_ip_ver, ip_dst, iface);
	if (eth_cache == NULL) {
		/*
		 * Note: the first packet to each new destination
		 * will always be dropped, since we don't have an
		 * Ethernet cache entry for it.
		 */
		return -1;
	}

	if (pkt_copy_cached_eth_header(m, eth_cache, iface->l2_len_out))
		return -1;

	return 0;
}

static void
fill_eth_hdr_reverse(struct gatekeeper_if *iface, struct rte_ether_hdr *eth_hdr,
	struct gt_packet_headers *pkt_info)
{
	struct rte_ether_hdr *raw_eth =
		(struct rte_ether_hdr *)pkt_info->l2_hdr;
	rte_ether_addr_copy(&raw_eth->s_addr, &eth_hdr->d_addr);
	rte_ether_addr_copy(&raw_eth->d_addr, &eth_hdr->s_addr);
	if (iface->vlan_insert) {
		fill_vlan_hdr(eth_hdr, iface->vlan_tag_be,
			pkt_info->outer_ethertype);
	} else {
		eth_hdr->ether_type =
			rte_cpu_to_be_16(pkt_info->outer_ethertype);
	}
}

/*
 * When creating a new notification packet, set all of the header
 * fields from each layer as much as possible. Fields that need to
 * wait to be filled until the packet is ready to be sent are
 * filled in prep_notify_pkt().
 */
static void
fill_notify_pkt_hdr(struct rte_mbuf *notify_pkt,
	struct gt_packet_headers *pkt_info, struct gt_config *gt_conf)
{
	uint16_t ethertype = pkt_info->outer_ethertype;
	struct rte_ether_hdr *notify_eth;
	struct rte_ipv4_hdr *notify_ipv4 = NULL;
	struct rte_ipv6_hdr *notify_ipv6 = NULL;
	struct rte_udp_hdr *notify_udp;
	struct ggu_common_hdr *notify_ggu;
	struct gatekeeper_if *iface = &gt_conf->net->front;
	size_t l2_len = iface->l2_len_out;

	if (ethertype == RTE_ETHER_TYPE_IPV4) {
		notify_eth = (struct rte_ether_hdr *)rte_pktmbuf_append(
			notify_pkt, l2_len + sizeof(struct rte_ipv4_hdr) +
			sizeof(struct rte_udp_hdr) +
			sizeof(struct ggu_common_hdr));
		notify_ipv4 = (struct rte_ipv4_hdr *)
			((uint8_t *)notify_eth + l2_len);
		notify_udp = (struct rte_udp_hdr *)&notify_ipv4[1];
		notify_ggu = (struct ggu_common_hdr *)&notify_udp[1];
	} else if (likely(ethertype == RTE_ETHER_TYPE_IPV6)) {
		notify_eth = (struct rte_ether_hdr *)rte_pktmbuf_append(
			notify_pkt, l2_len + sizeof(struct rte_ipv6_hdr) +
			sizeof(struct rte_udp_hdr) +
			sizeof(struct ggu_common_hdr));
		notify_ipv6 = (struct rte_ipv6_hdr *)
			((uint8_t *)notify_eth + l2_len);
		notify_udp = (struct rte_udp_hdr *)&notify_ipv6[1];
		notify_ggu = (struct ggu_common_hdr *)&notify_udp[1];
	} else
		rte_panic("Unexpected condition: gt fills up a notify packet with unknown ethernet type %hu\n",
			ethertype);

	memset(notify_ggu, 0, sizeof(*notify_ggu));
	notify_ggu->version = GGU_PD_VER;

	/* Fill up the link-layer header. */
	fill_eth_hdr_reverse(iface, notify_eth, pkt_info);
	notify_pkt->l2_len = l2_len;

	/* Fill up the IP header. */
	if (ethertype == RTE_ETHER_TYPE_IPV4) {
		struct rte_ipv4_hdr *ipv4_hdr =
			(struct rte_ipv4_hdr *)pkt_info->outer_l3_hdr;
		/* Fill up the IPv4 header. */
		notify_ipv4->version_ihl = IP_VHL_DEF;
		notify_ipv4->packet_id = 0;
		notify_ipv4->fragment_offset = IP_DN_FRAGMENT_FLAG;
		notify_ipv4->time_to_live = IP_DEFTTL;
		notify_ipv4->next_proto_id = IPPROTO_UDP;
		/* The source address is the Grantor server IP address. */
		notify_ipv4->src_addr = ipv4_hdr->dst_addr;
		/*
		 * The destination address is the
		 * Gatekeeper server IP address.
		 */
		notify_ipv4->dst_addr = ipv4_hdr->src_addr;

		notify_pkt->l3_len = sizeof(struct rte_ipv4_hdr);
		notify_pkt->ol_flags |= PKT_TX_IPV4;

		/* IPv4 checksum set in prep_notify_pkt(). */
	} else if (likely(ethertype == RTE_ETHER_TYPE_IPV6)) {
		struct rte_ipv6_hdr *ipv6_hdr =
			(struct rte_ipv6_hdr *)pkt_info->outer_l3_hdr;
		/* Fill up the outer IPv6 header. */
		notify_ipv6->vtc_flow =
			rte_cpu_to_be_32(IPv6_DEFAULT_VTC_FLOW);
		notify_ipv6->proto = IPPROTO_UDP; 
		notify_ipv6->hop_limits = iface->ipv6_default_hop_limits;

		rte_memcpy(notify_ipv6->src_addr, ipv6_hdr->dst_addr,
			sizeof(notify_ipv6->src_addr));
		rte_memcpy(notify_ipv6->dst_addr, ipv6_hdr->src_addr,
			sizeof(notify_ipv6->dst_addr));

		notify_pkt->l3_len = sizeof(struct rte_ipv6_hdr);
		notify_pkt->ol_flags |= PKT_TX_IPV6;
	}

	/* Fill up the UDP header. */
	notify_udp->src_port = gt_conf->ggu_src_port;
	notify_udp->dst_port = gt_conf->ggu_dst_port;

	notify_pkt->l4_len = sizeof(struct rte_udp_hdr);
}

static void
print_unsent_policy(struct ggu_policy *policy,
	__attribute__((unused)) void *arg)
{
	int ret;
	char err_msg[1024];

	switch (policy->state) {
	case GK_REQUEST:
		ret = snprintf(err_msg, sizeof(err_msg),
			"gt: GK_REQUEST is not a policy decision; there is a bug in the Lua policy\n");
		break;
	case GK_GRANTED:
		ret = snprintf(err_msg, sizeof(err_msg),
			"gt: failed to send out the notification to Gatekeeper with policy decision [state: GK_GRANTED (%hhu), tx_rate_kib_sec: %u, cap_expire_sec: %u, next_renewal_ms: %u, renewal_step_ms: %u]",
			policy->state, policy->params.granted.tx_rate_kib_sec,
			policy->params.granted.cap_expire_sec,
			policy->params.granted.next_renewal_ms,
			policy->params.granted.renewal_step_ms);
		break;
	case GK_DECLINED:
		ret = snprintf(err_msg, sizeof(err_msg),
			"gt: failed to send out the notification to Gatekeeper with policy decision [state: GK_DECLINED (%hhu), expire_sec: %u]",
			policy->state, policy->params.declined.expire_sec);
		break;
	case GK_BPF: {
		uint64_t *c = policy->params.bpf.cookie.mem;

		RTE_BUILD_BUG_ON(RTE_DIM(policy->params.bpf.cookie.mem) != 8);

		ret = snprintf(err_msg, sizeof(err_msg),
			"gt: failed to send out the notification to Gatekeeper with policy decision [state: GK_BPF (%hhu), expire_sec: %u, program_index=%u, cookie="
			"%016" PRIx64 ", %016" PRIx64 ", %016" PRIx64 ", %016" PRIx64
			", %016" PRIx64 ", %016" PRIx64 ", %016" PRIx64 ", %016" PRIx64 "]",
			policy->state, policy->params.bpf.expire_sec,
			policy->params.bpf.program_index,
			rte_cpu_to_be_64(c[0]), rte_cpu_to_be_64(c[1]),
			rte_cpu_to_be_64(c[2]), rte_cpu_to_be_64(c[3]),
			rte_cpu_to_be_64(c[4]), rte_cpu_to_be_64(c[5]),
			rte_cpu_to_be_64(c[6]), rte_cpu_to_be_64(c[7]));
		break;
	}
	default:
		ret = snprintf(err_msg, sizeof(err_msg),
			"gt: unknown policy decision with state %hhu at %s, there is a bug in the Lua policy\n",
			policy->state, __func__);
		break;
	}

	RTE_VERIFY(ret > 0 && ret < (int)sizeof(err_msg));
	print_flow_err_msg(&policy->flow, err_msg);
}

/* Print all unsent policy decisions in a notification packet. */
static void
print_unsent_policies(struct ggu_notify_pkt *ggu_pkt)
{
	unsigned int offset = ggu_pkt->buf->l2_len + ggu_pkt->buf->l3_len +
		sizeof(struct rte_udp_hdr) + sizeof(struct ggu_common_hdr);
	struct ggu_decision *ggu_decision = rte_pktmbuf_mtod_offset(
		ggu_pkt->buf, struct ggu_decision *, offset);
	unsigned int decision_list_len = ggu_pkt->buf->data_len - offset;
	ggu_policy_iterator(ggu_decision, decision_list_len,
		print_unsent_policy, NULL, "gt");
}

/*
 * Find the notification packet being buffered for the Gatekeeper
 * server specified in @pkt_info, if any.
 */
static struct ggu_notify_pkt *
find_notify_pkt(struct gt_config *gt_conf, struct gt_packet_headers *pkt_info,
	struct gt_instance *instance)
{
	unsigned int i;

	if (instance->num_ggu_pkts == 0)
		return NULL;

	for (i = 0; i < gt_conf->max_ggu_notify_pkts; i++) {
		struct ggu_notify_pkt *ggu_pkt = &instance->ggu_pkts[i];

		if (ggu_pkt->buf == NULL)
			continue;

		if (pkt_info->outer_ethertype != ggu_pkt->ipaddr.proto)
			continue;

		if (ggu_pkt->ipaddr.proto == RTE_ETHER_TYPE_IPV4) {
			struct rte_ipv4_hdr *ipv4_hdr =
				(struct rte_ipv4_hdr *)pkt_info->outer_l3_hdr;
			if (ggu_pkt->ipaddr.ip.v4.s_addr ==
					ipv4_hdr->src_addr)
				return ggu_pkt;
		} else if (likely(ggu_pkt->ipaddr.proto ==
				RTE_ETHER_TYPE_IPV6)) {
			struct rte_ipv6_hdr *ipv6_hdr =
				(struct rte_ipv6_hdr *)pkt_info->outer_l3_hdr;
			if (ipv6_addrs_equal(ipv6_hdr->src_addr,
					ggu_pkt->ipaddr.ip.v6.s6_addr))
				return ggu_pkt;
		}
	}
	return NULL;
}

static void
prep_notify_pkt(struct ggu_notify_pkt *ggu_pkt, struct gatekeeper_if *iface)
{
	/*
	 * Complete the packet fields that can only be done
	 * when the packet is ready to be transmitted.
	 */
	struct rte_udp_hdr *notify_udp;

	/*
	 * Datagram length needs to be set before calling
	 * rte_ipv*_udptcp_cksum(). Although it doesn't
	 * need to be set for rte_ipv*_phdr_cksum(), do
	 * it here to avoid calculating it in multiple places.
	 */
	uint16_t dgram_len_be =
		rte_cpu_to_be_16((uint16_t)(ggu_pkt->buf->data_len -
			ggu_pkt->buf->l2_len - ggu_pkt->buf->l3_len));

	if (ggu_pkt->ipaddr.proto == RTE_ETHER_TYPE_IPV4) {
		struct rte_ipv4_hdr *notify_ipv4 =
			rte_pktmbuf_mtod_offset(ggu_pkt->buf,
				struct rte_ipv4_hdr *,
				ggu_pkt->buf->l2_len);
		notify_ipv4->total_length = rte_cpu_to_be_16(
			ggu_pkt->buf->data_len - ggu_pkt->buf->l2_len);

		set_ipv4_checksum(iface, ggu_pkt->buf, notify_ipv4);

		notify_udp = rte_pktmbuf_mtod_offset(ggu_pkt->buf,
			struct rte_udp_hdr *,
			ggu_pkt->buf->l2_len + ggu_pkt->buf->l3_len);
		notify_udp->dgram_len = dgram_len_be;
		if (likely(iface->ipv4_hw_udp_cksum)) {
			/* Offload the UDP checksum. */
			ggu_pkt->buf->ol_flags |= PKT_TX_UDP_CKSUM;
			notify_udp->dgram_cksum =
				rte_ipv4_phdr_cksum(notify_ipv4,
					ggu_pkt->buf->ol_flags);
		} else {
			notify_udp->dgram_cksum = 0;
			notify_udp->dgram_cksum =
				rte_ipv4_udptcp_cksum(notify_ipv4,
					notify_udp);
		}
	} else if (likely(ggu_pkt->ipaddr.proto == RTE_ETHER_TYPE_IPV6)) {
		struct rte_ipv6_hdr *notify_ipv6 =
			rte_pktmbuf_mtod_offset(ggu_pkt->buf,
				struct rte_ipv6_hdr *, ggu_pkt->buf->l2_len);
		/*
		 * Distinct from @dgram_len_be because the IPv6
		 * payload field could in theory include the length
		 * of any extension headers.
		 */
		notify_ipv6->payload_len = rte_cpu_to_be_16(
			ggu_pkt->buf->data_len - ggu_pkt->buf->l2_len -
			sizeof(struct rte_ipv6_hdr));

		notify_udp = rte_pktmbuf_mtod_offset(ggu_pkt->buf,
			struct rte_udp_hdr *,
			ggu_pkt->buf->l2_len + ggu_pkt->buf->l3_len);
		notify_udp->dgram_len = dgram_len_be;
		if (likely(iface->ipv6_hw_udp_cksum)) {
			/* Offload the UDP checksum. */
			ggu_pkt->buf->ol_flags |= PKT_TX_UDP_CKSUM;
			notify_udp->dgram_cksum =
				rte_ipv6_phdr_cksum(notify_ipv6,
					ggu_pkt->buf->ol_flags);
		} else {
			notify_udp->dgram_cksum = 0;
			notify_udp->dgram_cksum =
				rte_ipv6_udptcp_cksum(notify_ipv6,
					notify_udp);
		}
	} else {
		rte_panic("Unexpected condition: gt at lcore %u sending notification packet to Gatekeeper server with unknown IP version %hu\n",
			rte_lcore_id(), ggu_pkt->ipaddr.proto);
	}
}

static void
send_notify_pkt(struct gt_config *gt_conf, struct gt_instance *instance,
	struct ggu_notify_pkt *ggu_pkt)
{
	prep_notify_pkt(ggu_pkt, &gt_conf->net->front);

	if (rte_eth_tx_burst(gt_conf->net->front.id,
			instance->tx_queue, &ggu_pkt->buf, 1) != 1) {
		print_unsent_policies(ggu_pkt);
		rte_pktmbuf_free(ggu_pkt->buf);
	}

	ggu_pkt->buf = NULL;
	instance->num_ggu_pkts--;
}

/* Send all saved policy decision notification packets being buffered. */
static void
flush_notify_pkts(struct gt_config *gt_conf, struct gt_instance *instance)
{
	unsigned int max_pkts = gt_conf->max_ggu_notify_pkts;
	struct rte_mbuf *bufs[max_pkts];
	int num_to_send = 0;
	int num_sent;
	int sent_count = 0;
	unsigned int i;

	if (instance->ggu_pkts == NULL || instance->num_ggu_pkts == 0)
		return;

	for (i = 0; i < max_pkts; i++) {
		struct ggu_notify_pkt *ggu_pkt = &instance->ggu_pkts[i];

		if (ggu_pkt->buf == NULL)
			continue;

		prep_notify_pkt(ggu_pkt, &gt_conf->net->front);
		bufs[num_to_send++] = ggu_pkt->buf;
	}

	num_sent = rte_eth_tx_burst(gt_conf->net->front.id,
		instance->tx_queue, bufs, num_to_send);

	for (i = 0; i < max_pkts; i++) {
		struct ggu_notify_pkt *ggu_pkt = &instance->ggu_pkts[i];

		if (ggu_pkt->buf == NULL)
			continue;

		if (unlikely(num_sent != num_to_send)) {
			if (sent_count < num_sent)
				sent_count++;
			else {
				print_unsent_policies(ggu_pkt);
				rte_pktmbuf_free(ggu_pkt->buf);
			}
		}

		ggu_pkt->buf = NULL;
		instance->num_ggu_pkts--;
	}

	RTE_VERIFY(instance->num_ggu_pkts == 0);
}

/*
 * Start building a new notification packet for the Gatekeeper
 * server indicated by @pkt_info.
 *
 * If there's no more room for a notification packet, then
 * send a random one to make room.
 */
static struct ggu_notify_pkt *
add_notify_pkt(struct gt_config *gt_conf, struct gt_instance *instance,
	struct gt_packet_headers *pkt_info)
{
	unsigned int max_pkts = gt_conf->max_ggu_notify_pkts;
	struct ggu_notify_pkt *ggu_pkt = NULL;
	unsigned int lcore_id = rte_lcore_id();
	unsigned int i;

	/* Find an available packet, sending a packet if necessary. */
	if (instance->num_ggu_pkts == max_pkts) {
		int idx = rte_rand() % max_pkts;
		ggu_pkt = &instance->ggu_pkts[idx];
		send_notify_pkt(gt_conf, instance, ggu_pkt);
	} else {
		for (i = 0; i < max_pkts; i++) {
			if (instance->ggu_pkts[i].buf == NULL) {
				ggu_pkt = &instance->ggu_pkts[i];
				break;
			}
		}
	}
	RTE_VERIFY(ggu_pkt != NULL);

	ggu_pkt->ipaddr.proto = pkt_info->outer_ethertype;
	if (ggu_pkt->ipaddr.proto == RTE_ETHER_TYPE_IPV4) {
		struct rte_ipv4_hdr *ipv4_hdr =
			(struct rte_ipv4_hdr *)pkt_info->outer_l3_hdr;
		ggu_pkt->ipaddr.ip.v4.s_addr = ipv4_hdr->src_addr;
	} else if (likely(ggu_pkt->ipaddr.proto == RTE_ETHER_TYPE_IPV6)) {
		struct rte_ipv6_hdr *ipv6_hdr =
			(struct rte_ipv6_hdr *)pkt_info->outer_l3_hdr;
		rte_memcpy(ggu_pkt->ipaddr.ip.v6.s6_addr, ipv6_hdr->src_addr,
			sizeof(ggu_pkt->ipaddr.ip.v6.s6_addr));
	} else {
		rte_panic("Unexpected condition: gt at lcore %u adding to notification packet to Gatekeeper server with unknown IP version %hu\n",
			lcore_id, ggu_pkt->ipaddr.proto);
	}

	ggu_pkt->buf = rte_pktmbuf_alloc(instance->mp);
	if (ggu_pkt->buf == NULL) {
		GT_LOG(ERR,
			"Failed to allocate notification packet on lcore %u\n",
			lcore_id);
		return NULL;
	}

	fill_notify_pkt_hdr(ggu_pkt->buf, pkt_info, gt_conf);

	instance->num_ggu_pkts++;
	return ggu_pkt;
}

/*
 * Return how many 4 bytes are used in @cookie.
 * All bytes after that are zeros.
 */
static unsigned int
find_cookie_len_4by(struct gk_bpf_cookie *cookie, unsigned int cookie_len)
{
	uint32_t *p = (uint32_t *)cookie;
	unsigned int n;
	int i;

	RTE_VERIFY(cookie_len <= sizeof(*cookie));

	n = cookie_len / 4;
	if (unlikely(cookie_len % 4 != 0))
		n++;

	for (i = n - 1; i >= 0; i--)
		if (p[i] != 0)
			return i + 1;
	return 0;
}

/*
 * To estimate the maximum size of an on-the-wire policy decision,
 * sum the size of the decision prefix (type and length fields) with
 * the size of the in-memory GGU policy struct. This is a slight
 * overestimate, which is acceptable for determining whether a
 * packet has enough room for another decision.
 */
#define GGU_MAX_DECISION_LEN (sizeof(struct ggu_decision) + \
	sizeof(struct ggu_policy))

/*
 * Add a policy decision to a notification packet. If a notification
 * does not exist for this Gatekeeper server, then create one.
 */
static void
fill_notify_pkt(struct ggu_policy *policy,
	struct gt_packet_headers *pkt_info, struct gt_instance *instance,
	struct gt_config *gt_conf)
{
	struct ggu_notify_pkt *ggu_pkt;
	struct ggu_decision *ggu_decision;
	size_t params_offset;
	int cookie_len_4by = 0;

	if (unlikely(policy->flow.proto != RTE_ETHER_TYPE_IPV4
			&& policy->flow.proto != RTE_ETHER_TYPE_IPV6)) {
		GT_LOG(ERR, "Policy decision with unknown protocol %u\n",
			policy->flow.proto);
		return;
	}

	switch (policy->state) {
	case GK_GRANTED:
	case GK_DECLINED:
		break;
	case GK_BPF:
		if (unlikely(policy->params.bpf.cookie_len >
				sizeof(policy->params.bpf.cookie))) {
			GT_LOG(ERR, "Policy BPF decision with cookie length too long: %u\n",
				policy->params.bpf.cookie_len);
			print_unsent_policy(policy, NULL);
			return;
		}
		break;
	default:
		/* The state GK_REQUEST is unexpected here. */
		print_unsent_policy(policy, NULL);
		return;
	}

	/* Get a GGU packet. */
	ggu_pkt = find_notify_pkt(gt_conf, pkt_info, instance);
	if (ggu_pkt == NULL) {
		ggu_pkt = add_notify_pkt(gt_conf, instance, pkt_info);
		if (ggu_pkt == NULL) {
			print_unsent_policy(policy, NULL);
			return;
		}
	}

	/* Fill up the policy decision. */

	if (policy->flow.proto == RTE_ETHER_TYPE_IPV4
			&& policy->state == GK_DECLINED) {
		ggu_decision = (struct ggu_decision *)
			rte_pktmbuf_append(ggu_pkt->buf,
				sizeof(*ggu_decision) +
				sizeof(policy->flow.f.v4) +
				sizeof(policy->params.declined));
		ggu_decision->type = GGU_DEC_IPV4_DECLINED;
		rte_memcpy(ggu_decision->ip_flow, &policy->flow.f.v4,
			sizeof(policy->flow.f.v4));
		params_offset = sizeof(policy->flow.f.v4);
	} else if (policy->flow.proto == RTE_ETHER_TYPE_IPV6
			&& policy->state == GK_DECLINED) {
		ggu_decision = (struct ggu_decision *)
			rte_pktmbuf_append(ggu_pkt->buf,
				sizeof(*ggu_decision) +
				sizeof(policy->flow.f.v6) +
				sizeof(policy->params.declined));
		ggu_decision->type = GGU_DEC_IPV6_DECLINED;
		rte_memcpy(ggu_decision->ip_flow, &policy->flow.f.v6,
			sizeof(policy->flow.f.v6));
		params_offset = sizeof(policy->flow.f.v6);
	} else if (policy->flow.proto == RTE_ETHER_TYPE_IPV4
			&& policy->state == GK_GRANTED) {
		ggu_decision = (struct ggu_decision *)
			rte_pktmbuf_append(ggu_pkt->buf,
				sizeof(*ggu_decision) +
				sizeof(policy->flow.f.v4) +
				sizeof(policy->params.granted));
		ggu_decision->type = GGU_DEC_IPV4_GRANTED;
		rte_memcpy(ggu_decision->ip_flow, &policy->flow.f.v4,
			sizeof(policy->flow.f.v4));
		params_offset = sizeof(policy->flow.f.v4);
	} else if (policy->flow.proto == RTE_ETHER_TYPE_IPV6
			&& policy->state == GK_GRANTED) {
		ggu_decision = (struct ggu_decision *)
			rte_pktmbuf_append(ggu_pkt->buf,
				sizeof(*ggu_decision) +
				sizeof(policy->flow.f.v6) +
				sizeof(policy->params.granted));
		ggu_decision->type = GGU_DEC_IPV6_GRANTED;
		rte_memcpy(ggu_decision->ip_flow, &policy->flow.f.v6,
			sizeof(policy->flow.f.v6));
		params_offset = sizeof(policy->flow.f.v6);
	} else if (policy->flow.proto == RTE_ETHER_TYPE_IPV4
			&& policy->state == GK_BPF) {
		cookie_len_4by = find_cookie_len_4by(&policy->params.bpf.cookie,
			policy->params.bpf.cookie_len);
		ggu_decision = (struct ggu_decision *)
			rte_pktmbuf_append(ggu_pkt->buf,
				sizeof(*ggu_decision) +
				sizeof(policy->flow.f.v4) +
				sizeof(struct ggu_bpf_wire) +
				cookie_len_4by * 4);
		ggu_decision->type = GGU_DEC_IPV4_BPF;
		rte_memcpy(ggu_decision->ip_flow, &policy->flow.f.v4,
			sizeof(policy->flow.f.v4));
		params_offset = sizeof(policy->flow.f.v4);
	} else if (likely(policy->flow.proto == RTE_ETHER_TYPE_IPV6
			&& policy->state == GK_BPF)) {
		cookie_len_4by = find_cookie_len_4by(&policy->params.bpf.cookie,
			policy->params.bpf.cookie_len);
		ggu_decision = (struct ggu_decision *)
			rte_pktmbuf_append(ggu_pkt->buf,
				sizeof(*ggu_decision) +
				sizeof(policy->flow.f.v6) +
				sizeof(struct ggu_bpf_wire) +
				cookie_len_4by * 4);
		ggu_decision->type = GGU_DEC_IPV6_BPF;
		rte_memcpy(ggu_decision->ip_flow, &policy->flow.f.v6,
			sizeof(policy->flow.f.v6));
		params_offset = sizeof(policy->flow.f.v6);
	} else
		rte_panic("Unexpected condition: gt fills up a notify packet with unexpected policy state %u\n",
			policy->state);

	switch (policy->state) {
	case GK_GRANTED: {
		struct ggu_granted *granted_be = (struct ggu_granted *)
			(ggu_decision->ip_flow + params_offset);
		granted_be->tx_rate_kib_sec = rte_cpu_to_be_32(
			policy->params.granted.tx_rate_kib_sec);
		granted_be->cap_expire_sec = rte_cpu_to_be_32(
			policy->params.granted.cap_expire_sec);
		granted_be->next_renewal_ms = rte_cpu_to_be_32(
			policy->params.granted.next_renewal_ms);
		granted_be->renewal_step_ms = rte_cpu_to_be_32(
			policy->params.granted.renewal_step_ms);
		break;
	}
	case GK_DECLINED: {
		struct ggu_declined *declined_be = (struct ggu_declined *)
			(ggu_decision->ip_flow + params_offset);
		declined_be->expire_sec = rte_cpu_to_be_32(
			policy->params.declined.expire_sec);
		break;
	}
	case GK_BPF: {
		struct ggu_bpf_wire *bpf_wire_be = (struct ggu_bpf_wire *)
			(ggu_decision->ip_flow + params_offset);
		bpf_wire_be->expire_sec = rte_cpu_to_be_32(
			policy->params.bpf.expire_sec);
		bpf_wire_be->program_index = policy->params.bpf.program_index;
		bpf_wire_be->reserved = 0;
		bpf_wire_be->cookie_len_4by = cookie_len_4by;
		/*
		 * It's reposibility of the BPF program to put
		 * the cookie in network order (if needed) since Gatekeeper
		 * does not know how the cookie is used.
		 */
		rte_memcpy(bpf_wire_be->cookie, &policy->params.bpf.cookie,
			cookie_len_4by * 4);
		break;
	}
	default:
		rte_panic("Unexpected condition: gt fills up a notify packet parameters with unexpected policy state %u\n",
			policy->state);
	}

	ggu_decision->res1 = 0;
	ggu_decision->res2 = 0;

	/*
	 * If we're close to the end of the packet, possibly
	 * without room for another decision, send it now.
	 */
	if (rte_pktmbuf_tailroom(ggu_pkt->buf) < GGU_MAX_DECISION_LEN)
		send_notify_pkt(gt_conf, instance, ggu_pkt);
}

/*
 * Use the @dr to notify the GK
 * about the punishment policies on declined flows
 * with fragmented packets.
 */
static void 
process_death_row(int punish, struct rte_ip_frag_death_row *death_row,
	struct gt_instance *instance, struct gt_config *gt_conf)
{
	uint32_t i;

	for (i = 0; i < death_row->cnt; i++) {
		int ret;
		struct gt_packet_headers pkt_info;
		struct ggu_policy policy;

		if (!punish)
			goto free_packet;

		ret = gt_parse_incoming_pkt(death_row->row[i], &pkt_info);
		if (ret < 0) {
			GT_LOG(WARNING,
				"Failed to parse the fragments at %s, and the packet doesn't trigger any policy consultation at all\n",
				__func__);
			rte_pktmbuf_free(death_row->row[i]);
			continue;
		}

		/*
		 * Given the gravity of the issue,
		 * we must send a decline to the gatekeeper server
		 * to expire in 10 minutes and log our failsafe
		 * action here.
		 * Otherwise, a misconfigured grantor server can put
		 * a large deployment at risk.
		 */
		ret = lookup_frag_punish_policy_decision(
			&pkt_info, &policy, instance);
		if (ret < 0) {
			policy.state = GK_DECLINED;
			policy.params.declined.expire_sec = 600;
			GT_LOG(WARNING,
				"Failed to lookup the punishment policy for the packet fragment! Our failsafe action is to decline the flow for 10 minutes\n");
		}

		/*
		 * Add the policy decision to the notification
		 * packet to be sent to the GT-GK Unit.
		 */
		fill_notify_pkt(&policy, &pkt_info, instance, gt_conf);

free_packet:
		rte_pktmbuf_free(death_row->row[i]);
	}

	death_row->cnt = 0;
}

static void
gt_process_unparsed_incoming_pkt(struct acl_search *acl4,
	struct acl_search *acl6, uint16_t *num_arp, struct rte_mbuf **arp_bufs,
	struct rte_mbuf *pkt, uint16_t outer_ethertype)
{
	switch (outer_ethertype) {
	case RTE_ETHER_TYPE_IPV4:
		add_pkt_acl(acl4, pkt);
		return;
	case RTE_ETHER_TYPE_IPV6:
		add_pkt_acl(acl6, pkt);
		return;
	case RTE_ETHER_TYPE_ARP:
		arp_bufs[(*num_arp)++] = pkt;
		return;
	}

	log_unknown_l2("gt", outer_ethertype);
	rte_pktmbuf_free(pkt);
}

static void
return_message(struct gt_instance *instance)
{
	int ret;
	unsigned lcore_id = rte_lcore_id();
	size_t reply_len;
	struct dynamic_config *dy_conf = get_dy_conf();
	struct dy_cmd_entry *entry;
	const char *reply_msg = lua_tolstring(instance->lua_state, -1, &reply_len);
	if (reply_msg == NULL) {
		GT_LOG(WARNING, "gt: new lua update returned a NULL message at lcore %u\n",
			lcore_id);
		goto out;
	}

	entry = mb_alloc_entry(&dy_conf->mb);
	if (entry == NULL) {
		GT_LOG(ERR, "gt: failed to send new lua update return to Dynamic config block at lcore %d\n",
			dy_conf->lcore_id);
		goto out;
	}

	if (unlikely(reply_len > RETURN_MSG_MAX_LEN)) {
		GT_LOG(WARNING,
			"gt: the return message length (%lu) exceeds the limit (%d) at lcore %u\n",
			reply_len, RETURN_MSG_MAX_LEN, lcore_id);

		reply_len = RETURN_MSG_MAX_LEN;
	}

	entry->op = GT_UPDATE_POLICY_RETURN;
	entry->u.gt.gt_lcore = lcore_id;
	entry->u.gt.length = reply_len;
	rte_memcpy(entry->u.gt.return_msg, reply_msg, reply_len);

	ret = mb_send_entry(&dy_conf->mb, entry);
	if (ret != 0) {
		GT_LOG(ERR, "gt: failed to send new lua update return to Dynamic config block at lcore %d\n",
			dy_conf->lcore_id);
	}

out:
	rte_atomic16_inc(&dy_conf->num_returned_instances);
}

static void
process_gt_cmd(struct gt_cmd_entry *entry, struct gt_instance *instance)
{
	switch (entry->op) {
	case GT_UPDATE_POLICY:
		lua_close(instance->lua_state);
		instance->lua_state = entry->u.lua_state;

		GT_LOG(NOTICE,
			"Successfully updated the lua state at lcore %u\n",
			rte_lcore_id());
		break;

	case GT_UPDATE_POLICY_INCREMENTALLY:
		/* Load the compiled Lua bytecode, and run it. */
		if ((luaL_loadbuffer(instance->lua_state,
				entry->u.bc.lua_bytecode, entry->u.bc.len,
				"incremental_update_of_gt_lua_state") != 0) ||
				(lua_pcall(instance->lua_state, 0,
					!!entry->u.bc.is_returned, 0) != 0)) {
			GT_LOG(ERR, "gt: failed to incrementally update lua state at lcore %u: %s\n",
				rte_lcore_id(),
				lua_tostring(instance->lua_state, -1));
		} else {
			GT_LOG(NOTICE,
				"Successfully updated the lua state incrementally at lcore %u\n",
				rte_lcore_id());
		}

		if (entry->u.bc.is_returned) {
			return_message(instance);
			lua_pop(instance->lua_state, 1);
		}

		rte_free(entry->u.bc.lua_bytecode);
		break;

	default:
		GT_LOG(ERR, "Unknown command operation %u\n", entry->op);
		break;
	}
}

static void
process_cmds_from_mailbox(struct gt_instance *instance,
	struct gt_config *gt_conf)
{
	int i;
	int num_cmd;
	struct gt_cmd_entry *gt_cmds[gt_conf->mailbox_burst_size];

	/* Load a set of commands from its mailbox ring. */
	num_cmd = mb_dequeue_burst(&instance->mb,
		(void **)gt_cmds, gt_conf->mailbox_burst_size);

	for (i = 0; i < num_cmd; i++) {
		process_gt_cmd(gt_cmds[i], instance);
		mb_free_entry(&instance->mb, gt_cmds[i]);
	}
}

static inline void
prefetch0_128_bytes(void *pointer)
{
#if RTE_CACHE_LINE_SIZE == 64
	rte_prefetch0(pointer);
	rte_prefetch0(((char *)pointer) + RTE_CACHE_LINE_SIZE);
#elif RTE_CACHE_LINE_SIZE == 128
	rte_prefetch0(pointer);
#else
#error "Unsupported cache line size"
#endif
}

static int
gt_proc(void *arg)
{
	unsigned int lcore = rte_lcore_id();
	struct gt_config *gt_conf = (struct gt_config *)arg;
	unsigned int block_idx = get_block_idx(gt_conf, lcore);
	struct gt_instance *instance = &gt_conf->instances[block_idx];

	uint64_t last_tsc = rte_rdtsc();
	uint16_t port = gt_conf->net->front.id;
	uint16_t rx_queue = instance->rx_queue;
	uint16_t tx_queue = instance->tx_queue;
	uint64_t frag_scan_timeout_cycles = round(
		gt_conf->frag_scan_timeout_ms * rte_get_tsc_hz() / 1000.);
	unsigned int batch = 0;
	/*
	 * The mbuf death row contains
	 * packets to be freed.
	 */
	struct rte_ip_frag_death_row death_row;
	uint16_t gt_max_pkt_burst;
	bool reassembling_enabled = gt_conf->reassembling_enabled;

	death_row.cnt = 0;
	gt_max_pkt_burst = gt_conf->max_pkt_burst;

	GT_LOG(NOTICE, "The GT block is running at lcore = %u\n", lcore);

	gt_conf_hold(gt_conf);

	while (likely(!exiting)) {
		int i;
		int ret;
		uint16_t num_rx;
		uint16_t num_tx = 0;
		uint16_t num_tx_succ;
		uint16_t num_arp = 0;
		uint64_t cur_tsc = rte_rdtsc();
		struct rte_mbuf *rx_bufs[gt_max_pkt_burst];
		struct rte_mbuf *tx_bufs[gt_max_pkt_burst];
		struct rte_mbuf *arp_bufs[gt_max_pkt_burst];
		DEFINE_ACL_SEARCH(acl4, gt_max_pkt_burst);
		DEFINE_ACL_SEARCH(acl6, gt_max_pkt_burst);

		/* Load a set of packets from the front NIC. */
		num_rx = rte_eth_rx_burst(port, rx_queue, rx_bufs,
			gt_max_pkt_burst);

		if (unlikely(num_rx == 0)) {
			process_cmds_from_mailbox(instance, gt_conf);
			flush_notify_pkts(gt_conf, instance);
			continue;
		}

		/*
		 * Note that GT blocks expect packets that are encapsulated.
		 *
		 * This prefetch is enough to load Ethernet header (14 bytes),
		 * optional Ethernet VLAN header (8 bytes), and either
		 * two IPv4 headers without options (20*2 bytes), or
		 * two IPv6 headers without options (40*2 bytes).
		 * IPv4: 14 + 8 + 20*2 = 62
		 * IPv6: 14 + 8 + 40*2 = 102
		 */
		for (i = 0; i < num_rx; i++) {
			prefetch0_128_bytes(rte_pktmbuf_mtod_offset(
				rx_bufs[i], void *, 0));
		}

		for (i = 0; i < num_rx; i++) {
			struct rte_mbuf *m = rx_bufs[i];
			struct gt_packet_headers pkt_info;
			struct ggu_policy policy;

			/*
			 * Only request packets and priority packets
			 * with capabilities about to expire go through a
			 * policy decision.
			 *
			 * Other packets will be fowarded directly.
			 */
			ret = gt_parse_incoming_pkt(m, &pkt_info);
			if (ret < 0) {
				gt_process_unparsed_incoming_pkt(
					&acl4, &acl6, &num_arp, arp_bufs,
					m, pkt_info.outer_ethertype);
				continue;
			}

			/*
			 * If packet reassembling at Grantor servers
			 * is enabled, and it is a fragmented packet,
			 * then try to reassemble.
			 */
			if (reassembling_enabled && pkt_info.frag) {
				m = gt_reassemble_incoming_pkt(
					m, cur_tsc, &pkt_info,
					&death_row, instance);

				/* Process the death packets. */
				process_death_row(m == NULL, &death_row,
					instance, gt_conf);

				if (m == NULL)
					continue;

				ret = gt_parse_incoming_pkt(
					m, &pkt_info);
				if (ret < 0) {
					gt_process_unparsed_incoming_pkt(
						&acl4, &acl6, &num_arp,
						arp_bufs, m,
						pkt_info.outer_ethertype);
					continue;
				}
			}

			if (unlikely(!is_valid_dest_addr(gt_conf, &pkt_info))) {
				print_ip_err_msg(&pkt_info);
				rte_pktmbuf_free(m);
				continue;
			}

			if (pkt_info.priority <= PRIORITY_GRANTED) {
				ret = decap_and_fill_eth(m, gt_conf,
					&pkt_info, instance);
				if (ret < 0)
					rte_pktmbuf_free(m);
				else
					tx_bufs[num_tx++] = m;
				continue;
			}

			/*
			 * Lookup the policy decision.
			 *
			 * The policy, which is defined by a Lua script,
			 * decides which capabilities to grant or decline,
			 * the maximum receiving rate of the granted
			 * capabilities, and when each decision expires.
			 */
			ret = lookup_policy_decision(
				&pkt_info, &policy, instance);
			if (ret < 0) {
				rte_pktmbuf_free(m);
				continue;
			}

			/*
			 * Add the policy decision to the notification
			 * packet to be sent to the GT-GK Unit.
			 */
			fill_notify_pkt(&policy, &pkt_info, instance, gt_conf);

			if (ret != 0) {
				ret = decap_and_fill_eth(m, gt_conf,
					&pkt_info, instance);
				if (ret < 0)
					rte_pktmbuf_free(m);
				else
					tx_bufs[num_tx++] = m;
			} else
				rte_pktmbuf_free(m);
		}

		/* Send burst of TX packets, to second port of pair. */
		num_tx_succ = rte_eth_tx_burst(port, tx_queue,
			tx_bufs, num_tx);

		/*
		 * XXX #71 Do something better here!
		 * For now, free any unsent packets.
		 */
		if (unlikely(num_tx_succ < num_tx)) {
			for (i = num_tx_succ; i < num_tx; i++)
				rte_pktmbuf_free(tx_bufs[i]);
		}

		if (num_arp > 0)
			submit_arp(arp_bufs, num_arp, &gt_conf->net->front);

		process_pkts_acl(&gt_conf->net->front, lcore, &acl4,
			RTE_ETHER_TYPE_IPV4);
		process_pkts_acl(&gt_conf->net->front, lcore, &acl6,
			RTE_ETHER_TYPE_IPV6);

		process_cmds_from_mailbox(instance, gt_conf);

		if (reassembling_enabled && cur_tsc - last_tsc >=
				frag_scan_timeout_cycles) {
			RTE_VERIFY(death_row.cnt == 0);
			rte_frag_table_del_expired_entries(instance->frag_tbl,
				&death_row, cur_tsc);

			/* Process the death packets. */
			process_death_row(true, &death_row,
				instance, gt_conf);

			last_tsc = rte_rdtsc();
		}

		batch = (batch + 1) % gt_conf->batch_interval;
		if (batch == 0)
			flush_notify_pkts(gt_conf, instance);
	}

	GT_LOG(NOTICE, "The GT block at lcore = %u is exiting\n", lcore);

	return gt_conf_put(gt_conf);
}

struct gt_config *
alloc_gt_conf(void)
{
	return rte_calloc("gt_config", 1, sizeof(struct gt_config), 0);
}

static inline void
cleanup_gt_instance(struct gt_config *gt_conf, struct gt_instance *instance)
{
	destroy_mempool(instance->mp);
	destroy_mailbox(&instance->mb);

	flush_notify_pkts(gt_conf, instance);
	rte_free(instance->ggu_pkts);
	instance->ggu_pkts = NULL;

	if (instance->frag_tbl != NULL) {
		rte_ip_frag_table_destroy(instance->frag_tbl);
		instance->frag_tbl = NULL;
	}

	destroy_neigh_hash_table(&instance->neigh6);
	destroy_neigh_hash_table(&instance->neigh);

	lua_close(instance->lua_state);
	instance->lua_state = NULL;
}

static int
cleanup_gt(struct gt_config *gt_conf)
{
	int i;
	for (i = 0; i < gt_conf->num_lcores; i++)
		cleanup_gt_instance(gt_conf, &gt_conf->instances[i]);

	rte_free(gt_conf->lua_policy_file);
	rte_free(gt_conf->lua_base_directory);
	rte_free(gt_conf->instances);
	rte_free(gt_conf->lcores);
	rte_free(gt_conf);

	return 0;
}

int
gt_conf_put(struct gt_config *gt_conf)
{
	/*
	 * Atomically decrements the atomic counter (v) by one and returns true 
	 * if the result is 0, or false in all other cases.
	 */
	if (rte_atomic32_dec_and_test(&gt_conf->ref_cnt))
		return cleanup_gt(gt_conf);

	return 0;
}

/* XXX #143 Search for another comment on this issue for an explanation. */
#if 0
static void *
alloc_lua_mem_in_dpdk(void *ud, void *ptr,
	__attribute__((unused))size_t osize, size_t nsize)
{
	if (nsize == 0) {
		rte_free(ptr);
		return NULL;
	}

	if (ptr == NULL) {
		int socket = (intptr_t)ud;
		return rte_malloc_socket(__func__, nsize, 0, socket);
	}

	return rte_realloc(ptr, nsize, 0);
}
#endif

static lua_State *
alloc_and_setup_lua_state(struct gt_config *gt_conf,
	__attribute__((unused))unsigned int lcore_id)
{
	int ret;
	char lua_entry_path[128];
	lua_State *lua_state;

	ret = snprintf(lua_entry_path, sizeof(lua_entry_path), "%s/%s",
		gt_conf->lua_base_directory, gt_conf->lua_policy_file);
	RTE_VERIFY(ret > 0 && ret < (int)sizeof(lua_entry_path));

	/*
	 * XXX #143 LuaJIT does not currently support
	 * lua_newstate() on 64-bit targets.
	 *
	 * Once lua_newstate() is available, the following call should
	 * replace the call to luaL_newstate() below:
	 * lua_state = lua_newstate(alloc_lua_mem_in_dpdk,
	 *	(void *)(intptr_t)rte_lcore_to_socket_id(lcore_id));
	 */
	lua_state = luaL_newstate();
	if (lua_state == NULL) {
		GT_LOG(ERR, "Failed to create new Lua state at %s\n",
			__func__);
		goto out;
	}

	luaL_openlibs(lua_state);
	lualpm_openlib(lua_state);
	set_lua_path(lua_state, gt_conf->lua_base_directory);
	ret = luaL_loadfile(lua_state, lua_entry_path);
	if (ret != 0) {
		GT_LOG(ERR, "%s\n", lua_tostring(lua_state, -1));
		goto clean_lua_state;
	}

	/* Run the loaded chunk. */
	ret = lua_pcall(lua_state, 0, 0, 0);
	if (ret != 0) {
		GT_LOG(ERR, "%s\n", lua_tostring(lua_state, -1));
		goto clean_lua_state;
	}

	return lua_state;

clean_lua_state:
	lua_close(lua_state);
out:
	return NULL;
}

static int
config_gt_instance(struct gt_config *gt_conf, unsigned int lcore_id)
{
	int ret;
	unsigned int block_idx = get_block_idx(gt_conf, lcore_id);

	/* Maximum TTL in cycles for each fragmented packet. */
	uint64_t frag_cycles = (rte_get_tsc_hz() + MS_PER_S - 1) /
		MS_PER_S * gt_conf->frag_max_flow_ttl_ms;
	struct gt_instance *instance = &gt_conf->instances[block_idx];

	instance->lua_state = alloc_and_setup_lua_state(gt_conf, lcore_id);
	if (instance->lua_state == NULL) {
		GT_LOG(ERR, "Failed to create new Lua state at lcore %u\n",
			lcore_id);
		ret = -1;
		goto out;
	}

	if (ipv4_if_configured(&gt_conf->net->front)) {
		ret = setup_neighbor_tbl(
			rte_lcore_to_socket_id(gt_conf->lcores[0]),
			lcore_id * RTE_MAX_LCORE + 0, RTE_ETHER_TYPE_IPV4,
			(1 << (32 - gt_conf->net->front.ip4_addr_plen)),
			&instance->neigh, custom_ipv4_hash_func);
		if (ret < 0)
			goto cleanup;
	}

	if (ipv6_if_configured(&gt_conf->net->front)) {
		ret = setup_neighbor_tbl(
			rte_lcore_to_socket_id(gt_conf->lcores[0]),
			lcore_id * RTE_MAX_LCORE + 1, RTE_ETHER_TYPE_IPV6,
			gt_conf->max_num_ipv6_neighbors, &instance->neigh6,
			DEFAULT_HASH_FUNC);
		if (ret < 0)
			goto cleanup;
	}

	if (!rte_is_power_of_2(gt_conf->frag_bucket_entries)) {
		GT_LOG(ERR,
			"Configuration error - the number of entries per bucket should be a power of 2, while it is %u\n",
			gt_conf->frag_bucket_entries);
		ret = -1;
		goto cleanup;
	}

	if (gt_conf->frag_max_entries > gt_conf->frag_bucket_num *
			gt_conf->frag_bucket_entries) {
		GT_LOG(ERR,
			"Configuration error - the maximum number of entries should be less than or equal to %u, while it is %u\n",
			gt_conf->frag_bucket_num *
			gt_conf->frag_bucket_entries,
			gt_conf->frag_max_entries);
		ret = -1;
		goto cleanup;
	}

	if (gt_conf->reassembling_enabled) {
		/* Setup the fragmentation table. */
		instance->frag_tbl = rte_ip_frag_table_create(
			gt_conf->frag_bucket_num,
			gt_conf->frag_bucket_entries, gt_conf->frag_max_entries,
			frag_cycles, rte_lcore_to_socket_id(lcore_id));
		if (instance->frag_tbl == NULL) {
			GT_LOG(ERR,
				"Failed to create fragmentation table at lcore %u\n",
				lcore_id);
			ret = -1;
			goto cleanup;
		}
	}

	instance->num_ggu_pkts = 0;
	instance->ggu_pkts = rte_calloc_socket(__func__,
		gt_conf->max_ggu_notify_pkts, sizeof(struct ggu_notify_pkt), 0,
		rte_lcore_to_socket_id(lcore_id));
	if (instance->ggu_pkts == NULL) {
		GT_LOG(ERR,
			"Failed to allocate fixed array of Gatekeeper notification packets on lcore %u\n",
			lcore_id);
		ret = -1;
		goto cleanup;
	}

	ret = init_mailbox("gt", gt_conf->mailbox_max_entries_exp,
		sizeof(struct gt_cmd_entry), gt_conf->mailbox_mem_cache_size,
		lcore_id, &instance->mb);
	if (ret < 0)
		goto cleanup;

	goto out;

cleanup:
	cleanup_gt_instance(gt_conf, instance);

out:
	return ret;
}

static int
init_gt_instances(struct gt_config *gt_conf)
{
	int i;
	int ret;
	int num_succ_instances = 0;
	struct gt_instance *inst_ptr;
	/*
	 * (1) Need gt_conf->max_pkt_burst to read those packets
	 * from the queue of the NIC.
	 *
	 * (2) Need gt_conf->frag_max_entries for the fragment packets.
	 *
	 * Take the GGU packets into account as well.
	 *
	 * (3) The GGU packets that GT normally sends out.
	 *
	 * (4) As the GT blocks call process_death_row() to process
	 * the expired packets. In the worst case, process_death_row()
	 * needs to notify Gatekeeper the decisions about all the packets
	 * in the fragmentation table via GGU packets. However, the number
	 * of GGU packets is limited by gt_conf->max_ggu_notify_pkts.
	 */
	unsigned int num_mbuf = calculate_mempool_config_para("gt",
		gt_conf->net, gt_conf->max_pkt_burst +
		gt_conf->frag_max_entries + gt_conf->max_pkt_burst +
		gt_conf->max_ggu_notify_pkts +
		(gt_conf->net->front.total_pkt_burst +
		gt_conf->num_lcores - 1) / gt_conf->num_lcores);

	/* Set up queue identifiers now for RSS, before instances start. */
	for (i = 0; i < gt_conf->num_lcores; i++) {
		unsigned int lcore = gt_conf->lcores[i];
		inst_ptr = &gt_conf->instances[i];

		inst_ptr->mp = create_pktmbuf_pool("gt", lcore, num_mbuf);
		if (inst_ptr->mp == NULL) {
			ret = -1;
			goto free_gt_instance;
		}

		ret = get_queue_id(&gt_conf->net->front, QUEUE_TYPE_RX, lcore,
			inst_ptr->mp);
		if (ret < 0) {
			GT_LOG(ERR, "Cannot assign an RX queue for the front interface for lcore %u\n",
				lcore);
			goto free_gt_instance;
		}
		inst_ptr->rx_queue = ret;

		ret = get_queue_id(&gt_conf->net->front, QUEUE_TYPE_TX, lcore,
			NULL);
		if (ret < 0) {
			GT_LOG(ERR, "Cannot assign a TX queue for the front interface for lcore %u\n",
				lcore);
			goto free_gt_instance;
		}
		inst_ptr->tx_queue = ret;

		/*
		 * Set up the lua state, neighbor tables, and
		 * fragmentation table for each instance, and
		 * initialize the policy tables.
		 */
		ret = config_gt_instance(gt_conf, lcore);
		if (ret < 0)
			goto free_gt_instance;

		num_succ_instances++;
	}

	ret = 0;
	goto out;

free_gt_instance:
	for (i = 0; i < num_succ_instances; i++)
		cleanup_gt_instance(gt_conf, &gt_conf->instances[i]);
out:
	return ret;
}

static int
gt_stage1(void *arg)
{
	int ret;
	struct gt_config *gt_conf = arg;

	gt_conf->instances = rte_calloc_socket(__func__, gt_conf->num_lcores,
		sizeof(struct gt_instance), 0,
		rte_lcore_to_socket_id(gt_conf->lcores[0]));
	if (gt_conf->instances == NULL) {
		ret = -1;
		goto out;
	}

	ret = init_gt_instances(gt_conf);
	if (ret < 0)
		goto instance;

	goto out;

instance:
	rte_free(gt_conf->instances);
	gt_conf->instances = NULL;
	rte_free(gt_conf->lcores);
	gt_conf->lcores = NULL;
out:
	return ret;
}

static int
gt_stage2(void *arg)
{
	struct gt_config *gt_conf = arg;
	int ret;

	if (gt_conf->net->front.rss) {
		ret = gt_setup_rss(gt_conf);
		if (ret < 0)
			goto cleanup;
	}

	return 0;

cleanup:
	cleanup_gt(gt_conf);
	return ret;
}

int
run_gt(struct net_config *net_conf, struct gt_config *gt_conf,
	const char *lua_base_directory, const char *lua_policy_file)
{
	int ret = -1, i;

	if (net_conf == NULL || gt_conf == NULL ||
			lua_base_directory == NULL ||
			lua_policy_file == NULL)
		goto out;

	gt_logtype = rte_log_register("gatekeeper.gt");
	if (gt_logtype < 0) {
		ret = -1;
		goto out;
	}
	ret = rte_log_set_level(gt_logtype, gt_conf->log_level);
	if (ret < 0) {
		ret = -1;
		goto out;
	}
	gt_conf->log_type = gt_logtype;

	for (i = 0; i < gt_conf->num_lcores; i++) {
		log_ratelimit_state_init(gt_conf->lcores[i],
			gt_conf->log_ratelimit_interval_ms,
			gt_conf->log_ratelimit_burst);
	}

	gt_conf->lua_base_directory = rte_strdup("lua_base_directory",
		lua_base_directory);
	if (gt_conf->lua_base_directory == NULL) {
		ret = -1;
		goto out;
	}

	gt_conf->lua_policy_file = rte_strdup("lua_policy_file",
		lua_policy_file);
	if (gt_conf->lua_policy_file == NULL)
		goto policy_dir;

	if (!(gt_conf->max_pkt_burst > 0))
		goto gt_config_file;

	if (gt_conf->batch_interval == 0) {
		GT_LOG(ERR, "Batch interval (%u) must be greater than 0\n",
			gt_conf->batch_interval);
		goto gt_config_file;
	}

	if (gt_conf->max_ggu_notify_pkts == 0) {
		GT_LOG(ERR,
			"Max number of GGU notification packets (%u) must be greater than 0\n",
			gt_conf->max_ggu_notify_pkts);
		goto gt_config_file;
	}

	gt_conf->net = net_conf;

	if (gt_conf->num_lcores <= 0)
		goto gt_config_file;

	ret = net_launch_at_stage1(net_conf, gt_conf->num_lcores,
		gt_conf->num_lcores, 0, 0, gt_stage1, gt_conf);
	if (ret < 0)
		goto gt_config_file;

	ret = launch_at_stage2(gt_stage2, gt_conf);
	if (ret < 0)
		goto stage1;

	for (i = 0; i < gt_conf->num_lcores; i++) {
		unsigned int lcore = gt_conf->lcores[i];
		ret = launch_at_stage3("gt", gt_proc, gt_conf, lcore);
		if (ret < 0) {
			pop_n_at_stage3(i);
			goto stage2;
		}
	}

	/*
	 * Convert port numbers in CPU order to network order
	 * to avoid recomputation for each packet.
	 */
	gt_conf->ggu_src_port = rte_cpu_to_be_16(gt_conf->ggu_src_port);
	gt_conf->ggu_dst_port = rte_cpu_to_be_16(gt_conf->ggu_dst_port);

	rte_atomic32_init(&gt_conf->ref_cnt);
	return 0;

stage2:
	pop_n_at_stage2(1);
stage1:
	pop_n_at_stage1(1);
gt_config_file:
	rte_free(gt_conf->lua_policy_file);
	gt_conf->lua_policy_file = NULL;
policy_dir:
	rte_free(gt_conf->lua_base_directory);
	gt_conf->lua_base_directory = NULL;
out:
	return ret;
}

int
l_update_gt_lua_states(lua_State *l)
{
	int i;
	uint32_t ctypeid;
	struct gt_config *gt_conf;
	uint32_t correct_ctypeid_gt_config = luaL_get_ctypeid(l,
		CTYPE_STRUCT_GT_CONFIG_PTR);

	/* First argument must be of type CTYPE_STRUCT_GT_CONFIG_PTR. */
	void *cdata = luaL_checkcdata(l, 1,
		&ctypeid, CTYPE_STRUCT_GT_CONFIG_PTR);
	if (ctypeid != correct_ctypeid_gt_config)
		luaL_error(l, "Expected `%s' as first argument",
			CTYPE_STRUCT_GT_CONFIG_PTR);

	gt_conf = *(struct gt_config **)cdata;

	for (i = 0; i < gt_conf->num_lcores; i++) {
		int ret;
		struct gt_cmd_entry *entry;
		struct gt_instance *instance = &gt_conf->instances[i];
		unsigned int lcore_id = gt_conf->lcores[i];
		lua_State *lua_state = alloc_and_setup_lua_state(gt_conf,
			lcore_id);
		if (lua_state == NULL) {
			luaL_error(l, "gt: failed to allocate new lua state to GT block %d at lcore %d\n",
				i, lcore_id);

			continue;
		}

		entry = mb_alloc_entry(&instance->mb);
		if (entry == NULL) {
			lua_close(lua_state);

			luaL_error(l, "gt: failed to send new lua state to GT block %d at lcore %d\n",
				i, lcore_id);

			continue;
		}

		entry->op = GT_UPDATE_POLICY;
		entry->u.lua_state = lua_state;

		ret = mb_send_entry(&instance->mb, entry);
		if (ret != 0) {
			lua_close(lua_state);

			luaL_error(l, "gt: failed to send new lua state to GT block %d at lcore %d\n",
				i, lcore_id);
		}
	}

	return 0;
}

/*
 * The prototype is needed, otherwise there will be a compilation error:
 * no previous prototype for 'gt_cpu_to_be_16' [-Werror=missing-prototypes]
 */
uint16_t gt_cpu_to_be_16(uint16_t x);
uint32_t gt_cpu_to_be_32(uint32_t x);
uint16_t gt_be_to_cpu_16(uint16_t x);
uint32_t gt_be_to_cpu_32(uint32_t x);

unsigned int gt_lcore_id(void);

/*
 * This function is only meant to be used in Lua policies.
 * If you need it in Gatekeeper's C code, use rte_cpu_to_be_16()
 */
uint16_t
gt_cpu_to_be_16(uint16_t x)
{
	return rte_cpu_to_be_16(x);
}

/*
 * This function is only meant to be used in Lua policies.
 * If you need it in Gatekeeper's C code, use rte_cpu_to_be_32()
 */
uint32_t
gt_cpu_to_be_32(uint32_t x)
{
	return rte_cpu_to_be_32(x);
}

/*
 * This function is only meant to be used in Lua policies.
 * If you need it in Gatekeeper's C code, use rte_be_to_cpu_16()
 */
uint16_t
gt_be_to_cpu_16(uint16_t x)
{
	return rte_be_to_cpu_16(x);
}

/*
 * This function is only meant to be used in Lua policies.
 * If you need it in Gatekeeper's C code, use rte_be_to_cpu_32()
 */
uint32_t
gt_be_to_cpu_32(uint32_t x)
{
	return rte_be_to_cpu_32(x);
}

/*
 * This function is only meant to be used in Lua policies.
 * If you need it in Gatekeeper's C code, use rte_lcore_id()
 */
unsigned int
gt_lcore_id(void)
{
	return rte_lcore_id();
}
