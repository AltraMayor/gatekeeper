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

#include <rte_log.h>
#include <rte_ether.h>
#include <rte_lcore.h>
#include <rte_malloc.h>
#include <rte_random.h>

#include "gatekeeper_fib.h"
#include "gatekeeper_lls.h"
#include "gatekeeper_acl.h"
#include "gatekeeper_ggu.h"
#include "gatekeeper_ipip.h"
#include "gatekeeper_gk.h"
#include "gatekeeper_gt.h"
#include "gatekeeper_lls.h"
#include "gatekeeper_main.h"
#include "gatekeeper_net.h"
#include "gatekeeper_launch.h"
#include "gatekeeper_l2.h"

/* TODO Get the install-path via Makefile. */
#define LUA_POLICY_BASE_DIR "./lua"
#define GRANTOR_CONFIG_FILE "policy.lua"

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
	uint8_t port_in = gt_conf->net->front.id;
	uint16_t gt_queues[gt_conf->num_lcores];

	for (i = 0; i < gt_conf->num_lcores; i++)
		gt_queues[i] = gt_conf->instances[i].rx_queue;

	return gatekeeper_setup_rss(port_in, gt_queues, gt_conf->num_lcores);
}

static int
gt_parse_incoming_pkt(struct rte_mbuf *pkt, struct gt_packet_headers *info)
{
	uint8_t inner_ip_ver;
	uint8_t encasulated_proto;
	uint16_t parsed_len;
	struct ether_hdr *eth_hdr = rte_pktmbuf_mtod(pkt, struct ether_hdr *);
	struct ipv4_hdr *outer_ipv4_hdr = NULL;
	struct ipv6_hdr *outer_ipv6_hdr = NULL;
	struct ipv4_hdr *inner_ipv4_hdr = NULL;
	struct ipv6_hdr *inner_ipv6_hdr = NULL;

	info->l2_hdr = eth_hdr;
	info->outer_ethertype = rte_be_to_cpu_16(pkt_in_skip_l2(pkt, eth_hdr,
		&info->outer_l3_hdr));
	parsed_len = pkt_in_l2_hdr_len(pkt);

	switch (info->outer_ethertype) {
	case ETHER_TYPE_IPv4:
		if (pkt->data_len < parsed_len + sizeof(struct ipv4_hdr))
			return -1;

		outer_ipv4_hdr = (struct ipv4_hdr *)info->outer_l3_hdr;
		parsed_len += sizeof(struct ipv4_hdr);
		info->priority = (outer_ipv4_hdr->type_of_service >> 2);
		info->outer_ecn =
			outer_ipv4_hdr->type_of_service & IPTOS_ECN_MASK;
		encasulated_proto = outer_ipv4_hdr->next_proto_id;
		break;
	case ETHER_TYPE_IPv6:
		if (pkt->data_len < parsed_len + sizeof(struct ipv6_hdr))
			return -1;

		outer_ipv6_hdr = (struct ipv6_hdr *)info->outer_l3_hdr;
		parsed_len += sizeof(struct ipv6_hdr);
		info->priority = (((outer_ipv6_hdr->vtc_flow >> 20)
			& 0xFF) >> 2);
		info->outer_ecn =
			(outer_ipv6_hdr->vtc_flow >> 20) & IPTOS_ECN_MASK;
		encasulated_proto = outer_ipv6_hdr->proto;
		break;
	default:
		return -1;
	}

	if (encasulated_proto != IPPROTO_IPIP)
		return -1;

	/*
	 * Make sure that the packet has space for
	 * at least 4 bytes for the l4 header.
	 */
	if (pkt->data_len < parsed_len + sizeof(struct ipv4_hdr) + 4)
		return -1;

	if (outer_ipv4_hdr != NULL)
 		inner_ipv4_hdr = (struct ipv4_hdr *)&outer_ipv4_hdr[1];
	else
 		inner_ipv4_hdr = (struct ipv4_hdr *)&outer_ipv6_hdr[1];

 	inner_ip_ver = (inner_ipv4_hdr->version_ihl & 0xF0) >> 4;
	info->inner_l3_hdr = inner_ipv4_hdr;

	if (inner_ip_ver == 4) {
		info->inner_ip_ver = ETHER_TYPE_IPv4;
		info->l4_proto = inner_ipv4_hdr->next_proto_id;
		info->l4_hdr = &inner_ipv4_hdr[1];
	} else if (likely(inner_ip_ver == 6)) {
		/*
	 	 * Make sure that the packet has space for
		 * at least 4 bytes for the l4 header.
	 	 */
		if (pkt->data_len < parsed_len + sizeof(struct ipv6_hdr) + 4)
			return -1;

		inner_ipv6_hdr = (struct ipv6_hdr *)info->inner_l3_hdr;
		info->inner_ip_ver = ETHER_TYPE_IPv6;
		info->l4_proto = inner_ipv6_hdr->proto;
		info->l4_hdr = &inner_ipv6_hdr[1];
	} else
		return -1;

	return 0;
}

static int
lookup_policy_decision(struct gt_packet_headers *pkt_info,
	struct ggu_policy *policy, struct gt_instance *instance)
{
	policy->flow.proto = pkt_info->inner_ip_ver;
	if (pkt_info->inner_ip_ver == ETHER_TYPE_IPv4) {
		struct ipv4_hdr *ip4_hdr = (struct ipv4_hdr *)pkt_info->inner_l3_hdr;

		policy->flow.f.v4.src = ip4_hdr->src_addr;
		policy->flow.f.v4.dst = ip4_hdr->dst_addr;
	} else if (likely(pkt_info->inner_ip_ver == ETHER_TYPE_IPv6)) {
		struct ipv6_hdr *ip6_hdr = (struct ipv6_hdr *)pkt_info->inner_l3_hdr;

		rte_memcpy(policy->flow.f.v6.src, ip6_hdr->src_addr,
			sizeof(policy->flow.f.v6.src));
		rte_memcpy(policy->flow.f.v6.dst, ip6_hdr->dst_addr,
			sizeof(policy->flow.f.v6.dst));
	} else
		rte_panic("Unexpected condition: gt block at lcore %u lookups policy decision for an non-IP packet!\n",
			rte_lcore_id());

	lua_getglobal(instance->lua_state, "lookup_policy");
	lua_pushlightuserdata(instance->lua_state, pkt_info);
	lua_pushlightuserdata(instance->lua_state, policy);

	if (lua_pcall(instance->lua_state, 2, 0, 0) != 0) {
		RTE_LOG(ERR, GATEKEEPER,
			"gt: error running function `lookup_policy': %s, at lcore %u\n",
			lua_tostring(instance->lua_state, -1), rte_lcore_id());
		return -1;
	}

	return 0;
}

static inline bool
is_valid_dest_addr(struct gt_config *gt_conf,
	struct gt_packet_headers *pkt_info)
{
	return (pkt_info->outer_ethertype == ETHER_TYPE_IPv4 &&
			((struct ipv4_hdr *)
			pkt_info->outer_l3_hdr)->dst_addr
			== gt_conf->net->front.ip4_addr.s_addr)
			||
			(pkt_info->outer_ethertype == ETHER_TYPE_IPv6 &&
			memcmp(((struct ipv6_hdr *)
			pkt_info->outer_l3_hdr)->dst_addr,
			gt_conf->net->front.ip6_addr.s6_addr,
			sizeof(gt_conf->net->front.ip6_addr) == 0));
}

static void
print_ip_err_msg(struct gt_packet_headers *pkt_info)
{
	char src[128];
	char dst[128];

	if (pkt_info->outer_ethertype == ETHER_TYPE_IPv4) {
		if (inet_ntop(AF_INET, &((struct ipv4_hdr *)
				pkt_info->outer_l3_hdr)->src_addr,
				src, sizeof(struct in_addr)) == NULL) {
			RTE_LOG(ERR, GATEKEEPER, "gt: %s: failed to convert a number to an IPv4 address (%s)\n",
				__func__, strerror(errno));
			return;
		}

		if (inet_ntop(AF_INET, &((struct ipv4_hdr *)
				pkt_info->outer_l3_hdr)->dst_addr,
				dst, sizeof(struct in_addr)) == NULL) {
			RTE_LOG(ERR, GATEKEEPER, "gt: %s: failed to convert a number to an IPv4 address (%s)\n",
				__func__, strerror(errno));
			return;
		}
	} else {
		if (inet_ntop(AF_INET6, &((struct ipv6_hdr *)
				pkt_info->outer_l3_hdr)->src_addr,
				src, sizeof(struct in6_addr)) == NULL) {
			RTE_LOG(ERR, GATEKEEPER, "gt: %s: failed to convert a number to an IPv6 address (%s)\n",
				__func__, strerror(errno));
			return;
		}

		if (inet_ntop(AF_INET6, &((struct ipv6_hdr *)
				pkt_info->outer_l3_hdr)->dst_addr,
				dst, sizeof(struct in6_addr)) == NULL) {
			RTE_LOG(ERR, GATEKEEPER, "gt: %s: failed to convert a number to an IPv6 address (%s)\n",
				__func__, strerror(errno));
			return;
		}
	}

	RTE_LOG(ALERT, GATEKEEPER,
		"gt: receiving a packet with IP source address %s, and destination address %s, whose destination IP address is not the Grantor server itself.!\n",
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
	ether_addr_copy(&map->ha, &eth_cache->l2_hdr.eth_hdr.d_addr);
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

	if (inner_ip_ver == ETHER_TYPE_IPv4) {
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

	ether_addr_copy(&iface->eth_addr, &eth_cache->l2_hdr.eth_hdr.s_addr);
	rte_atomic32_set(&eth_cache->ref_cnt, 1);

	if (inner_ip_ver == ETHER_TYPE_IPv4) {
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

	if (ip_ver == ETHER_TYPE_IPv4) {
		ret = put_arp(&eth_cache->ip_addr.ip.v4, rte_lcore_id());
		if (ret < 0)
			return ret;

		ret = rte_hash_del_key(neigh->hash_table,
			&eth_cache->ip_addr.ip.v4);
		if (ret < 0) {
			RTE_LOG(CRIT, GATEKEEPER,
				"gt: failed to delete an Ethernet cache entry from the IPv4 neighbor table at %s, we are not trying to recover from this failure!",
				__func__);
		}
		return ret;
	}

	if (likely(ip_ver == ETHER_TYPE_IPv6)) {
		ret = put_nd(&eth_cache->ip_addr.ip.v6, rte_lcore_id());
		if (ret < 0)
			return ret;

		ret = rte_hash_del_key(neigh->hash_table,
			&eth_cache->ip_addr.ip.v6);
		if (ret < 0) {
			RTE_LOG(CRIT, GATEKEEPER,
				"gt: failed to delete an Ethernet cache entry from the IPv6 neighbor table at %s, we are not trying to recover from this failure!",
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
	char ip[128];
	struct lls_config *lls_conf;
	struct ether_cache *eth_cache = lookup_ether_cache(neigh, ip_dst);
	if (eth_cache != NULL)
		return eth_cache;

	lls_conf = get_lls_conf();
	if (inner_ip_ver == ETHER_TYPE_IPv4) {
		if (!lls_conf->arp_cache.ip_in_subnet(iface, ip_dst)) {
			if (inet_ntop(AF_INET, ip_dst,
					ip, sizeof(ip)) == NULL) {
				RTE_LOG(ERR, GATEKEEPER,
					"gt: %s: failed to convert a number to an IPv4 address (%s)\n",
					__func__, strerror(errno));
				return NULL;
			}

			RTE_LOG(WARNING, GATEKEEPER,
				"gt: %s: receiving an IPv4 packet with destination IP address %s, which is not on the same subnet as the GT server!\n",
				__func__, ip);
			return NULL;
		}
	} else if (likely(inner_ip_ver == ETHER_TYPE_IPv6)) {
		if (!lls_conf->nd_cache.ip_in_subnet(iface, ip_dst)) {
			if (inet_ntop(AF_INET6, ip_dst,
					ip, sizeof(ip)) == NULL) {
				RTE_LOG(ERR, GATEKEEPER,
					"gt: %s: failed to convert a number to an IPv6 address (%s)\n",
					__func__, strerror(errno));
				return NULL;
			}

			RTE_LOG(WARNING, GATEKEEPER,
				"gt: %s: receiving an IPv6 packet with destination IP address %s, which is not on the same subnet as the GT server!\n",
				__func__, ip);
			return NULL;
		}
	} else
		return NULL;

	eth_cache = get_new_ether_cache(neigh);
	if (eth_cache == NULL) {
		ret = drop_cache_entry_randomly(neigh, inner_ip_ver);
		if (ret < 0)
			return NULL;

		eth_cache = get_new_ether_cache(neigh);
		if (eth_cache == NULL) {
			RTE_LOG(WARNING, GATEKEEPER,
				"gt: failed to get a new Ethernet cache entry from the neighbor hash table at %s, the cache is overflowing!\n",
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

	RTE_LOG(ERR, HASH,
		"Failed to add a cache entry to the neighbor hash table at %s\n",
		__func__);

	if (inner_ip_ver == ETHER_TYPE_IPv4)
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
	int bytes_to_add;

	if (pkt_info->inner_ip_ver == ETHER_TYPE_IPv4) {
		/*
		 * The Full-functionality Option for setting ECN bits in
		 * IP-in-IP packets. RFC 3168, section 9.1.1.
		 *
		 * If the outer header's ECN codepoint is CE and the inner
		 * header's ECN codepoint is not CE, set it and clear the
		 * checksum so that hardware can recompute it.
		 */
		struct ipv4_hdr *inner_ipv4_hdr = pkt_info->inner_l3_hdr;
		if (((inner_ipv4_hdr->type_of_service & IPTOS_ECN_MASK) !=
				IPTOS_ECN_CE) &&
				(pkt_info->outer_ecn == IPTOS_ECN_CE)) {
			inner_ipv4_hdr->type_of_service |= IPTOS_ECN_CE;
			inner_ipv4_hdr->hdr_checksum = 0;
		}

		neigh = &instance->neigh;
		ip_dst = &inner_ipv4_hdr->dst_addr;
	} else if (likely(pkt_info->inner_ip_ver == ETHER_TYPE_IPv6)) {
		/*
		 * Since there's no checksum in the IPv6 header, skip the
		 * extra comparisons and set the ECN bits if needed
		 * (even if it's redundant).
		 */
		struct ipv6_hdr *inner_ipv6_hdr = pkt_info->inner_l3_hdr;
		if (pkt_info->outer_ecn == IPTOS_ECN_CE)
			inner_ipv6_hdr->vtc_flow |= IPTOS_ECN_CE << 20;

		neigh = &instance->neigh6;
		ip_dst = inner_ipv6_hdr->dst_addr;
	} else
		return -1;

	bytes_to_add = pkt_info->outer_ethertype == ETHER_TYPE_IPv4
		? -sizeof(struct ipv4_hdr)
		: -sizeof(struct ipv6_hdr);

	if (adjust_pkt_len(m, &gt_conf->net->front,
			bytes_to_add) == NULL) {
		RTE_LOG(ERR, GATEKEEPER,
			"gt: could not adjust packet length\n");
		return -1;
	}

	/*
	 * The destination MAC address comes from LLS block.
	 */
	eth_cache = gt_neigh_get_ether_cache(neigh,
		pkt_info->inner_ip_ver, ip_dst, &gt_conf->net->front);
	if (eth_cache == NULL)
		return -1;

	if (pkt_copy_cached_eth_header(m, eth_cache,
			gt_conf->net->front.l2_len_out))
		return -1;

	return 0;
}

static void
fill_eth_hdr_reverse(struct gatekeeper_if *iface, struct ether_hdr *eth_hdr,
	struct gt_packet_headers *pkt_info)
{
	struct ether_hdr *raw_eth = (struct ether_hdr *)pkt_info->l2_hdr;
	ether_addr_copy(&raw_eth->s_addr, &eth_hdr->d_addr);
	ether_addr_copy(&raw_eth->d_addr, &eth_hdr->s_addr);
	if (iface->vlan_insert) {
		fill_vlan_hdr(eth_hdr, iface->vlan_tag_be,
			pkt_info->outer_ethertype);
	} else {
		eth_hdr->ether_type =
			rte_cpu_to_be_16(pkt_info->outer_ethertype);
	}
}

static struct rte_mbuf *
alloc_and_fill_notify_pkt(unsigned int socket, struct ggu_policy *policy,
	struct gt_packet_headers *pkt_info, struct gt_config *gt_conf)
{
	uint8_t *data;
	uint16_t ethertype = pkt_info->outer_ethertype;
	struct ether_hdr *notify_eth;
	struct ipv4_hdr *notify_ipv4 = NULL;
	struct ipv6_hdr *notify_ipv6 = NULL;
	struct udp_hdr *notify_udp;
	struct ggu_common_hdr *notify_ggu;
	size_t l2_len;

	struct rte_mbuf *notify_pkt = rte_pktmbuf_alloc(
		gt_conf->net->gatekeeper_pktmbuf_pool[socket]);
	if (notify_pkt == NULL) {
		RTE_LOG(ERR, MEMPOOL,
			"gt: failed to allocate notification packet!");
		return NULL;
	}

	l2_len = gt_conf->net->front.l2_len_out;
	if (ethertype == ETHER_TYPE_IPv4) {
		notify_eth = (struct ether_hdr *)rte_pktmbuf_append(notify_pkt,
			l2_len + sizeof(struct ipv4_hdr) +
			sizeof(struct udp_hdr) + sizeof(struct ggu_common_hdr));
		notify_ipv4 = (struct ipv4_hdr *)
			((uint8_t *)notify_eth + l2_len);
		notify_udp = (struct udp_hdr *)&notify_ipv4[1];
		notify_ggu = (struct ggu_common_hdr *)&notify_udp[1];
	} else if (ethertype == ETHER_TYPE_IPv6) {
		notify_eth = (struct ether_hdr *)rte_pktmbuf_append(notify_pkt,
			l2_len + sizeof(struct ipv6_hdr) +
			sizeof(struct udp_hdr) + sizeof(struct ggu_common_hdr));
		notify_ipv6 = (struct ipv6_hdr *)
			((uint8_t *)notify_eth + l2_len);
		notify_udp = (struct udp_hdr *)&notify_ipv6[1];
		notify_ggu = (struct ggu_common_hdr *)&notify_udp[1];
	} else
		rte_panic("Unexpected condition: gt fills up a notify packet with unknown ethernet type %hu\n",
			ethertype);

	/* Fill up the policy decision. */
	memset(notify_ggu, 0, sizeof(*notify_ggu));
	notify_ggu->v1 = GGU_PD_VER1;
	if (policy->flow.proto == ETHER_TYPE_IPv4
			&& policy->state == GK_DECLINED) {
		notify_ggu->n1 = 1;
		data = (uint8_t *)rte_pktmbuf_append(notify_pkt,
			sizeof(policy->flow.f.v4) +
			sizeof(policy->params.u.declined));
		rte_memcpy(data, &policy->flow.f.v4,
			sizeof(policy->flow.f.v4));
		rte_memcpy(data + sizeof(policy->flow.f.v4),
			&policy->params.u.declined,
			sizeof(policy->params.u.declined));
	} else if (policy->flow.proto == ETHER_TYPE_IPv6
			&& policy->state == GK_DECLINED) {
		notify_ggu->n2 = 1;
		data = (uint8_t *)rte_pktmbuf_append(notify_pkt,
			sizeof(policy->flow.f.v6) +
			sizeof(policy->params.u.declined));
		rte_memcpy(data, &policy->flow.f.v6,
			sizeof(policy->flow.f.v6));
		rte_memcpy(data + sizeof(policy->flow.f.v6),
			&policy->params.u.declined,
			sizeof(policy->params.u.declined));
	} else if (policy->flow.proto == ETHER_TYPE_IPv4
			&& policy->state == GK_GRANTED) {
		notify_ggu->n3 = 1;
		data = (uint8_t *)rte_pktmbuf_append(notify_pkt,
			sizeof(policy->flow.f.v4) +
			sizeof(policy->params.u.granted));
		rte_memcpy(data, &policy->flow.f.v4,
			sizeof(policy->flow.f.v4));
		rte_memcpy(data + sizeof(policy->flow.f.v4),
			&policy->params.u.granted,
			sizeof(policy->params.u.granted));
	} else if (policy->flow.proto == ETHER_TYPE_IPv6
			&& policy->state == GK_GRANTED) {
		notify_ggu->n4 = 1;
		data = (uint8_t *)rte_pktmbuf_append(notify_pkt,
			sizeof(policy->flow.f.v6) +
			sizeof(policy->params.u.granted));
		rte_memcpy(data, &policy->flow.f.v6,
			sizeof(policy->flow.f.v6));
		rte_memcpy(data + sizeof(policy->flow.f.v6),
			&policy->params.u.granted,
			sizeof(policy->params.u.granted));
	} else
		rte_panic("Unexpected condition: gt fills up a notify packet with unexpected policy state %u\n",
			policy->state);

	/* Fill up the link-layer header. */
	fill_eth_hdr_reverse(&gt_conf->net->front, notify_eth, pkt_info);
	notify_pkt->l2_len = l2_len;

	/* Fill up the IP header. */
	if (ethertype == ETHER_TYPE_IPv4) {
		struct ipv4_hdr *ipv4_hdr =
			(struct ipv4_hdr *)pkt_info->outer_l3_hdr;
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
		notify_ipv4->total_length = rte_cpu_to_be_16(
			notify_pkt->data_len - l2_len);

		/*
		 * The IP header checksum filed must be set to 0
		 * in order to offload the checksum calculation.
		 */
		notify_ipv4->hdr_checksum = 0;

		notify_pkt->ol_flags |= (PKT_TX_IPV4 |
			PKT_TX_IP_CKSUM | PKT_TX_UDP_CKSUM);
		notify_pkt->l3_len = sizeof(struct ipv4_hdr);

		/* Offload the UDP checksum. */
		notify_udp->dgram_cksum =
			rte_ipv4_phdr_cksum(notify_ipv4,
			notify_pkt->ol_flags);
	} else if (ethertype == ETHER_TYPE_IPv6) {
		struct ipv6_hdr *ipv6_hdr =
			(struct ipv6_hdr *)pkt_info->outer_l3_hdr;
		/* Fill up the outer IPv6 header. */
		notify_ipv6->vtc_flow =
			rte_cpu_to_be_32(IPv6_DEFAULT_VTC_FLOW);
		notify_ipv6->proto = IPPROTO_UDP; 
		notify_ipv6->hop_limits = IPv6_DEFAULT_HOP_LIMITS;

		rte_memcpy(notify_ipv6->src_addr, ipv6_hdr->dst_addr,
			sizeof(notify_ipv6->src_addr));
		rte_memcpy(notify_ipv6->dst_addr, ipv6_hdr->src_addr,
			sizeof(notify_ipv6->dst_addr));
		notify_ipv6->payload_len =
			rte_cpu_to_be_16(notify_pkt->data_len -
			l2_len - sizeof(struct ipv6_hdr));

		notify_pkt->ol_flags |= (PKT_TX_IPV6 |
			PKT_TX_IP_CKSUM | PKT_TX_UDP_CKSUM);
		notify_pkt->l3_len = sizeof(struct ipv6_hdr);

		/* Offload the UDP checksum. */
		notify_udp->dgram_cksum =
			rte_ipv6_phdr_cksum(notify_ipv6,
			notify_pkt->ol_flags);
	}

	/* Fill up the UDP header. */
	notify_udp->src_port = gt_conf->ggu_src_port;
	notify_udp->dst_port = gt_conf->ggu_dst_port;
	notify_udp->dgram_len = rte_cpu_to_be_16((uint16_t)(
		sizeof(*notify_udp) + sizeof(*notify_ggu) +
		(notify_ggu->n1 + notify_ggu->n3) *
		sizeof(policy->flow.f.v4) +
		(notify_ggu->n2 + notify_ggu->n4) *
		sizeof(policy->flow.f.v6) +
		(notify_ggu->n1 + notify_ggu->n2) *
		sizeof(policy->params.u.declined) + 
		(notify_ggu->n3 + notify_ggu->n4) *
		sizeof(policy->params.u.granted)));

	notify_pkt->l4_len = sizeof(struct udp_hdr);

	return notify_pkt;
}

static int
gt_proc(void *arg)
{
	unsigned int lcore = rte_lcore_id();
	unsigned int socket = rte_lcore_to_socket_id(lcore);
	struct gt_config *gt_conf = (struct gt_config *)arg;
	unsigned int block_idx = get_block_idx(gt_conf, lcore);
	struct gt_instance *instance = &gt_conf->instances[block_idx];

	uint8_t port = get_net_conf()->front.id;
	uint16_t rx_queue = instance->rx_queue;
	uint16_t tx_queue = instance->tx_queue;

	RTE_LOG(NOTICE, GATEKEEPER,
		"gt: the GT block is running at lcore = %u\n", lcore);

	gt_conf_hold(gt_conf);

	while (likely(!exiting)) {
		int i;
		uint16_t num_rx;
		uint16_t num_tx = 0;
		uint16_t num_tx_succ;
		uint16_t num_arp = 0;
		struct rte_mbuf *rx_bufs[GATEKEEPER_MAX_PKT_BURST];
		struct rte_mbuf *tx_bufs[GATEKEEPER_MAX_PKT_BURST];
		struct rte_mbuf *arp_bufs[GATEKEEPER_MAX_PKT_BURST];
		ACL_SEARCH_DEF(acl4);
		ACL_SEARCH_DEF(acl6);

		/* Load a set of packets from the front NIC. */
		num_rx = rte_eth_rx_burst(port, rx_queue, rx_bufs,
			GATEKEEPER_MAX_PKT_BURST);

		if (unlikely(num_rx == 0))
			continue;

		for (i = 0; i < num_rx; i++) {
			int ret;
			struct rte_mbuf *m = rx_bufs[i];
			struct gt_packet_headers pkt_info;
			struct ggu_policy policy;
			struct rte_mbuf *notify_pkt;

			/*
			 * Only request packets and priority packets
			 * with capabilities about to expire go through a
			 * policy decision.
			 *
			 * Other packets will be fowarded directly.
			 */
			ret = gt_parse_incoming_pkt(m, &pkt_info);
			if (ret < 0) {
				switch (pkt_info.outer_ethertype) {
				case ETHER_TYPE_IPv4:
					add_pkt_acl(&acl4, m);
					continue;
				case ETHER_TYPE_IPv6:
					add_pkt_acl(&acl6, m);
					continue;
				case ETHER_TYPE_ARP:
					arp_bufs[num_arp++] = m;
					continue;
				}

				RTE_LOG(ALERT, GATEKEEPER,
					"gt: parsing an invalid packet!\n");
				rte_pktmbuf_free(m);
				continue;
			}

			if (unlikely(!is_valid_dest_addr(gt_conf, &pkt_info))) {
				print_ip_err_msg(&pkt_info);
				rte_pktmbuf_free(m);
				continue;
			}

			if (pkt_info.priority <= 1) {
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
			 * TODO Reply in a batch.
			 * Reply the policy decision to GK-GT unit.
			 */
			notify_pkt = alloc_and_fill_notify_pkt(
				socket, &policy, &pkt_info, gt_conf);
			if (notify_pkt != NULL && rte_eth_tx_burst(
					port, tx_queue, &notify_pkt, 1) != 1)
				rte_pktmbuf_free(notify_pkt);

			if (policy.state == GK_GRANTED) {
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
		 * XXX Do something better here!
		 * For now, free any unsent packets.
		 */
		if (unlikely(num_tx_succ < num_tx)) {
			for (i = num_tx_succ; i < num_tx; i++)
				rte_pktmbuf_free(tx_bufs[i]);
		}

		if (num_arp > 0)
			submit_arp(arp_bufs, num_arp, &gt_conf->net->front);

		process_pkts_acl(&gt_conf->net->front, lcore, &acl4,
			ETHER_TYPE_IPv4);
		process_pkts_acl(&gt_conf->net->front, lcore, &acl6,
			ETHER_TYPE_IPv6);
	}

	RTE_LOG(NOTICE, GATEKEEPER,
		"gt: the GT block at lcore = %u is exiting\n", lcore);

	return gt_conf_put(gt_conf);
}

struct gt_config *
alloc_gt_conf(void)
{
	return rte_calloc("gt_config", 1, sizeof(struct gt_config), 0);
}

static inline void
cleanup_gt_instance(struct gt_instance *instance)
{
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
		cleanup_gt_instance(&gt_conf->instances[i]);

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

static int
config_gt_instance(struct gt_config *gt_conf, unsigned int lcore_id)
{
	int ret;
	char lua_entry_path[128];
	unsigned int block_idx = get_block_idx(gt_conf, lcore_id);
	struct gt_instance *instance = &gt_conf->instances[block_idx];

	ret = snprintf(lua_entry_path, sizeof(lua_entry_path), \
			"%s/%s", LUA_POLICY_BASE_DIR, GRANTOR_CONFIG_FILE);
	RTE_VERIFY(ret > 0 && ret < (int)sizeof(lua_entry_path));

	instance->lua_state = luaL_newstate();
	if (instance->lua_state == NULL) {
		RTE_LOG(ERR, GATEKEEPER,
			"gt: failed to create new Lua state at lcore %u!\n",
			lcore_id);
		ret = -1;
		goto out;
	}

	luaL_openlibs(instance->lua_state);
	set_lua_path(instance->lua_state, LUA_POLICY_BASE_DIR);
	ret = luaL_loadfile(instance->lua_state, lua_entry_path);
	if (ret != 0) {
		RTE_LOG(ERR, GATEKEEPER,
			"gt: %s!\n", lua_tostring(instance->lua_state, -1));
		ret = -1;
		goto cleanup;
	}

	/* Run the loaded chunk. */
	ret = lua_pcall(instance->lua_state, 0, 0, 0);
	if (ret != 0) {
		RTE_LOG(ERR, GATEKEEPER,
			"gt: %s!\n", lua_tostring(instance->lua_state, -1));
		ret = -1;
		goto cleanup;
	}

	if (gt_conf->net->front.configured_proto & CONFIGURED_IPV4) {
		ret = setup_neighbor_tbl(
			rte_lcore_to_socket_id(gt_conf->lcores[0]),
			lcore_id * RTE_MAX_LCORE + 0, ETHER_TYPE_IPv4,
			(1 << (32 - gt_conf->net->front.ip4_addr_plen)),
			&instance->neigh);
		if (ret < 0)
			goto cleanup;
	}

	if (gt_conf->net->front.configured_proto & CONFIGURED_IPV6) {
		ret = setup_neighbor_tbl(
			rte_lcore_to_socket_id(gt_conf->lcores[0]),
			lcore_id * RTE_MAX_LCORE + 1, ETHER_TYPE_IPv6,
			gt_conf->max_num_ipv6_neighbors, &instance->neigh6);
		if (ret < 0)
			goto cleanup;
	}

	goto out;

cleanup:
	cleanup_gt_instance(instance);

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

	/* Set up queue identifiers now for RSS, before instances start. */
	for (i = 0; i < gt_conf->num_lcores; i++) {
		unsigned int lcore = gt_conf->lcores[i];
		inst_ptr = &gt_conf->instances[i];

		ret = get_queue_id(&gt_conf->net->front, QUEUE_TYPE_RX, lcore);
		if (ret < 0) {
			RTE_LOG(ERR, GATEKEEPER, "gt: cannot assign an RX queue for the front interface for lcore %u\n",
				lcore);
			goto free_gt_instance;
		}
		inst_ptr->rx_queue = ret;

		ret = get_queue_id(&gt_conf->net->front, QUEUE_TYPE_TX, lcore);
		if (ret < 0) {
			RTE_LOG(ERR, GATEKEEPER, "gt: cannot assign a TX queue for the front interface for lcore %u\n",
				lcore);
			goto free_gt_instance;
		}
		inst_ptr->tx_queue = ret;

		/*
		 * Set up the lua state and neighbor tables for each instance,
		 * and initialize the policy tables.
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
		cleanup_gt_instance(&gt_conf->instances[i]);
out:
	return ret;
}

static int
gt_stage1(void *arg)
{
	int ret;
	struct gt_config *gt_conf = arg;

	gt_conf->instances = rte_calloc(__func__, gt_conf->num_lcores,
		sizeof(struct gt_instance), 0);
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
	int ret = gt_setup_rss(gt_conf);
	if (ret < 0)
		goto cleanup;

	return 0;

cleanup:
	cleanup_gt(gt_conf);
	return ret;
}

int
run_gt(struct net_config *net_conf, struct gt_config *gt_conf)
{
	int ret, i;

	if (net_conf == NULL || gt_conf == NULL) {
		ret = -1;
		goto out;
	}

	gt_conf->net = net_conf;

	if (gt_conf->num_lcores <= 0)
		goto success;

	ret = net_launch_at_stage1(net_conf, gt_conf->num_lcores,
		gt_conf->num_lcores, 0, 0, gt_stage1, gt_conf);
	if (ret < 0)
		goto out;

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

	goto success;

stage2:
	pop_n_at_stage2(1);
stage1:
	pop_n_at_stage1(1);
out:
	return ret;

success:
	rte_atomic32_init(&gt_conf->ref_cnt);
	return 0;
}
