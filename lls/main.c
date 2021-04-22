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

#include <alloca.h>
#include <stdbool.h>

#include <rte_cycles.h>
#include <rte_ethdev.h>
#include <rte_icmp.h>

#include "gatekeeper_config.h"
#include "gatekeeper_l2.h"
#include "gatekeeper_launch.h"
#include "gatekeeper_lls.h"
#include "gatekeeper_varip.h"
#include "arp.h"
#include "cache.h"
#include "nd.h"
#include "luajit-ffi-cdata.h"

/*
 * When using LACP, the requirement must be met:
 *
 *  - RX/TX burst functions must be invoked at least once every 100ms.
 *    To do so, the RX burst function is called with every iteration
 *    of the loop in lls_proc(), and lls_lacp_announce() fulfills the
 *    TX burst requirement on a timer that runs slightly more frequently
 *    than every 100ms, defined below.
 */
#define LLS_LACP_ANNOUNCE_INTERVAL_MS 99

/*
 * XXX #64 Don't alert user of LLS transmission failures while LACP
 * is still configuring, and warn the user if LACP is taking an
 * unusually long time to configure (since this could mean the
 * link partner does not have LACP configured).
 */

int lls_logtype;

static struct lls_config lls_conf = {
	.arp_cache = {
		.name = "arp",
		.iface_enabled = iface_arp_enabled,
		.ip_in_subnet = ipv4_in_subnet,
		.xmit_req = xmit_arp_req,
	},
	.nd_cache = {
		.name = "nd",
		.iface_enabled = iface_nd_enabled,
		.ip_in_subnet = ipv6_in_subnet,
		.xmit_req = xmit_nd_req,
	},
};

struct lls_config *
get_lls_conf(void)
{
	return &lls_conf;
}

static int
cleanup_lls(void)
{
	struct net_config *net_conf = lls_conf.net;
	if (lacp_enabled(net_conf, &net_conf->back))
		rte_timer_stop(&net_conf->back.lacp_timer);
	if (lacp_enabled(net_conf, &net_conf->front))
		rte_timer_stop(&net_conf->front.lacp_timer);
	if (nd_enabled(&lls_conf))
		lls_cache_destroy(&lls_conf.nd_cache);
	if (arp_enabled(&lls_conf))
		lls_cache_destroy(&lls_conf.arp_cache);
	rte_timer_stop(&lls_conf.log_timer);
	rte_timer_stop(&lls_conf.scan_timer);
	destroy_mailbox(&lls_conf.requests);
	destroy_mempool(lls_conf.mp);
	return 0;
}

int
hold_arp(lls_req_cb cb, void *arg, struct in_addr *ipv4, unsigned int lcore_id)
{
	if (arp_enabled(&lls_conf)) {
		struct lls_hold_req hold_req = {
			.cache = &lls_conf.arp_cache,
			.addr = {
				.proto = RTE_ETHER_TYPE_IPV4,
				.ip.v4 = *ipv4,
			},
			.hold = {
				.cb = cb,
				.arg = arg,
				.lcore_id = lcore_id,
			},
		};
		return lls_req(LLS_REQ_HOLD, &hold_req);
	}

	LLS_LOG(WARNING, "lcore %u called %s but ARP service is not enabled\n",
		lcore_id, __func__);
	return -1;
}

int
put_arp(struct in_addr *ipv4, unsigned int lcore_id)
{
	if (arp_enabled(&lls_conf)) {
		struct lls_put_req put_req = {
			.cache = &lls_conf.arp_cache,
			.addr = {
				.proto = RTE_ETHER_TYPE_IPV4,
				.ip.v4 = *ipv4,
			},
			.lcore_id = lcore_id,
		};
		return lls_req(LLS_REQ_PUT, &put_req);
	}

	LLS_LOG(WARNING, "lcore %u called %s but ARP service is not enabled\n",
		lcore_id, __func__);
	return -1;
}

int
hold_nd(lls_req_cb cb, void *arg, struct in6_addr *ipv6, unsigned int lcore_id)
{
	if (nd_enabled(&lls_conf)) {
		struct lls_hold_req hold_req = {
			.cache = &lls_conf.nd_cache,
			.addr = {
				.proto = RTE_ETHER_TYPE_IPV6,
				.ip.v6 = *ipv6,
			},
			.hold = {
				.cb = cb,
				.arg = arg,
				.lcore_id = lcore_id,
			},
		};
		return lls_req(LLS_REQ_HOLD, &hold_req);
	}

	LLS_LOG(WARNING, "lcore %u called %s but ND service is not enabled\n",
		lcore_id, __func__);
	return -1;
}

int
put_nd(struct in6_addr *ipv6, unsigned int lcore_id)
{
	if (nd_enabled(&lls_conf)) {
		struct lls_put_req put_req = {
			.cache = &lls_conf.nd_cache,
			.addr = {
				.proto = RTE_ETHER_TYPE_IPV6,
				.ip.v6 = *ipv6,
			},
			.lcore_id = lcore_id,
		};
		return lls_req(LLS_REQ_PUT, &put_req);
	}

	LLS_LOG(WARNING, "lcore %u called %s but ND service is not enabled\n",
		lcore_id, __func__);
	return -1;
}

#define ARP_REQ_SIZE(num_pkts) (offsetof(struct lls_request, end_of_header) + \
	sizeof(struct lls_arp_req) + sizeof(struct rte_mbuf *) * num_pkts)

void
submit_arp(struct rte_mbuf **pkts, unsigned int num_pkts,
	struct gatekeeper_if *iface)
{
	struct lls_arp_req *arp_req;
	int ret;

	RTE_VERIFY(num_pkts <= lls_conf.mailbox_max_pkt_sub);

	arp_req = alloca(ARP_REQ_SIZE(num_pkts));
	arp_req->num_pkts = num_pkts;
	arp_req->iface = iface;
	rte_memcpy(arp_req->pkts, pkts, sizeof(*arp_req->pkts) * num_pkts);

	ret = lls_req(LLS_REQ_ARP, arp_req);
	if (unlikely(ret < 0)) {
		unsigned int i;
		for (i = 0; i < num_pkts; i++)
			rte_pktmbuf_free(pkts[i]);
	}
}

#define ICMP_REQ_SIZE(num_pkts) (offsetof(struct lls_request, end_of_header) + \
	sizeof(struct lls_icmp_req) + sizeof(struct rte_mbuf *) * num_pkts)

static int
submit_icmp(struct rte_mbuf **pkts, unsigned int num_pkts,
	struct gatekeeper_if *iface)
{
	struct lls_icmp_req *icmp_req;
	int ret;

	RTE_VERIFY(num_pkts <= lls_conf.mailbox_max_pkt_sub);

	icmp_req = alloca(ICMP_REQ_SIZE(num_pkts));
	icmp_req->num_pkts = num_pkts;
	icmp_req->iface = iface;
	rte_memcpy(icmp_req->pkts, pkts, sizeof(*icmp_req->pkts) * num_pkts);

	ret = lls_req(LLS_REQ_ICMP, icmp_req);
	if (unlikely(ret < 0)) {
		unsigned int i;
		for (i = 0; i < num_pkts; i++)
			rte_pktmbuf_free(pkts[i]);
		return ret;
	}
	return 0;
}

/*
 * Match the packet if it fails to be classifed by ACL rules.
 *
 * Return values: 0 for successful match, and -ENOENT for no matching.
 */
static int
match_icmp(struct rte_mbuf *pkt, struct gatekeeper_if *iface)
{
	const uint16_t BE_ETHER_TYPE_IPv4 =
		rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
	struct rte_ether_hdr *eth_hdr =
		rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);
	struct rte_ipv4_hdr *ip4hdr;
	uint16_t ether_type_be = pkt_in_skip_l2(pkt, eth_hdr, (void **)&ip4hdr);
	size_t l2_len = pkt_in_l2_hdr_len(pkt);

	if (unlikely(ether_type_be != BE_ETHER_TYPE_IPv4))
		return -ENOENT;

	if (pkt->data_len < ICMP_PKT_MIN_LEN(l2_len))
		return -ENOENT;

	if (ip4hdr->dst_addr != iface->ip4_addr.s_addr)
		return -ENOENT;

	if (ip4hdr->next_proto_id != IPPROTO_ICMP)
		return -ENOENT;

	if (pkt->data_len < (ICMP_PKT_MIN_LEN(l2_len) +
			ipv4_hdr_len(ip4hdr) - sizeof(*ip4hdr)))
		return -ENOENT;

	if (rte_ipv4_frag_pkt_is_fragmented(ip4hdr)) {
		LLS_LOG(WARNING,
			"Received fragmented ICMP packets destined to this server at %s\n",
			__func__);
		return -ENOENT;
	}

	return 0;
}

#define ICMP6_REQ_SIZE(num_pkts) (offsetof(struct lls_request, end_of_header) + \
	sizeof(struct lls_icmp6_req) + sizeof(struct rte_mbuf *) * num_pkts)

static int
submit_icmp6(struct rte_mbuf **pkts, unsigned int num_pkts,
	struct gatekeeper_if *iface)
{
	struct lls_icmp6_req *icmp6_req;
	int ret;

	RTE_VERIFY(num_pkts <= lls_conf.mailbox_max_pkt_sub);

	icmp6_req = alloca(ICMP6_REQ_SIZE(num_pkts));
	icmp6_req->num_pkts = num_pkts;
	icmp6_req->iface = iface;
	rte_memcpy(icmp6_req->pkts, pkts, sizeof(*icmp6_req->pkts) * num_pkts);

	ret = lls_req(LLS_REQ_ICMP6, icmp6_req);
	if (unlikely(ret < 0)) {
		unsigned int i;
		for (i = 0; i < num_pkts; i++)
			rte_pktmbuf_free(pkts[i]);
		return ret;
	}
	return 0;
}

/*
 * Match the packet if it fails to be classifed by ACL rules.
 *
 * Return values: 0 for successful match, and -ENOENT for no matching.
 */
static int
match_icmp6(struct rte_mbuf *pkt, struct gatekeeper_if *iface)
{
	/*
	 * The ICMPv6 header offset in terms of the
	 * beginning of the IPv6 header.
	 */
	int icmpv6_offset;
	uint8_t nexthdr;
	const uint16_t BE_ETHER_TYPE_IPv6 =
		rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV6);
	struct rte_ether_hdr *eth_hdr =
		rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);
	struct rte_ipv6_hdr *ip6hdr;
	uint16_t ether_type_be = pkt_in_skip_l2(pkt, eth_hdr, (void **)&ip6hdr);
	size_t l2_len = pkt_in_l2_hdr_len(pkt);

	if (unlikely(ether_type_be != BE_ETHER_TYPE_IPv6))
		return -ENOENT;

	if (pkt->data_len < ICMPV6_PKT_MIN_LEN(l2_len))
		return -ENOENT;

	if ((memcmp(ip6hdr->dst_addr, &iface->ip6_addr,
			sizeof(iface->ip6_addr)) != 0) &&
			(memcmp(ip6hdr->dst_addr, &iface->ll_ip6_addr,
			sizeof(iface->ll_ip6_addr)) != 0) &&
			(memcmp(ip6hdr->dst_addr, &iface->ip6_mc_addr,
			sizeof(iface->ip6_mc_addr)) != 0) &&
			(memcmp(ip6hdr->dst_addr,
			&iface->ll_ip6_mc_addr,
			sizeof(iface->ll_ip6_mc_addr)) != 0) &&
			(memcmp(ip6hdr->dst_addr, &ip6_allnodes_mc_addr,
			sizeof(ip6_allnodes_mc_addr)) != 0))
		return -ENOENT;

	if (rte_ipv6_frag_get_ipv6_fragment_header(ip6hdr) != NULL) {
		LLS_LOG(WARNING,
			"Received fragmented ICMPv6 packets destined to this server at %s\n",
			__func__);
		return -ENOENT;
	}

	icmpv6_offset = ipv6_skip_exthdr(ip6hdr, pkt->data_len - l2_len,
		&nexthdr);
	if (icmpv6_offset < 0 || nexthdr != IPPROTO_ICMPV6)
		return -ENOENT;

	if (pkt->data_len < (ICMPV6_PKT_MIN_LEN(l2_len) +
			icmpv6_offset - sizeof(*ip6hdr)))
		return -ENOENT;

	return 0;
}

static void
rotate_log(__attribute__((unused)) struct rte_timer *timer,
	__attribute__((unused)) void *arg)
{
	gatekeeper_log_init();
}

static void
lls_scan(__attribute__((unused)) struct rte_timer *timer, void *arg)
{
	struct lls_config *lls_conf = (struct lls_config *)arg;
	if (arp_enabled(lls_conf))
		lls_cache_scan(lls_conf, &lls_conf->arp_cache);
	if (nd_enabled(lls_conf))
		lls_cache_scan(lls_conf, &lls_conf->nd_cache);
}

static void
lls_lacp_announce(__attribute__((unused)) struct rte_timer *timer, void *arg)
{
	struct gatekeeper_if *iface = (struct gatekeeper_if *)arg;
	uint16_t tx_queue = iface == &lls_conf.net->front
		? lls_conf.tx_queue_front
		: lls_conf.tx_queue_back;
	/*
	 * This function returns 0 when no packets are transmitted or
	 * when there's an error. Since we're asking for no packets to
	 * be transmitted, we can't differentiate between success and
	 * failure, so we don't check. However, if this fails repeatedly,
	 * the LACP bonding driver will log an error.
	 */
	rte_eth_tx_burst(iface->id, tx_queue, NULL, 0);
}

static inline int
lacp_timer_reset(struct lls_config *lls_conf, struct gatekeeper_if *iface)
{
	return rte_timer_reset(&iface->lacp_timer,
		(uint64_t)((LLS_LACP_ANNOUNCE_INTERVAL_MS / 1000.0) *
		rte_get_timer_hz()), PERIODICAL,
		lls_conf->lcore_id, lls_lacp_announce, iface);
}

static void
fillup_lls_dump_entry(struct lls_dump_entry *dentry, struct lls_map *map)
{
	dentry->stale = map->stale;
	dentry->port_id = map->port_id;
	dentry->addr = map->addr;
	rte_ether_addr_copy(&map->ha, &dentry->ha);
}

#define CTYPE_STRUCT_LLS_DUMP_ENTRY_PTR "struct lls_dump_entry *"

static void
list_lls(lua_State *l, struct lls_cache *cache)
{
	uint32_t next = 0;
	const void *key;
	void *data;
	int32_t index;
	void *cdata;
	uint32_t correct_ctypeid_lls_dentry = luaL_get_ctypeid(l,
		CTYPE_STRUCT_LLS_DUMP_ENTRY_PTR);

	index = rte_hash_iterate(cache->hash, (void *)&key, &data, &next);
	while (index >= 0) {
		struct lls_dump_entry dentry;
		struct lls_record *record = &cache->records[index];

		fillup_lls_dump_entry(&dentry, &record->map);

		lua_pushvalue(l, 2);
		lua_insert(l, 3);
		cdata = luaL_pushcdata(l, correct_ctypeid_lls_dentry,
			sizeof(struct lls_dump_entry *));
		*(struct lls_dump_entry **)cdata = &dentry;
		lua_insert(l, 4);

		lua_call(l, 2, 1);

		index = rte_hash_iterate(cache->hash,
			(void *)&key, &data, &next);
	}
}

static void
list_arp(lua_State *l, struct lls_config *lls_conf)
{
	if (!ipv4_configured(lls_conf->net))
		return;
	list_lls(l, &lls_conf->arp_cache);
}

static void
list_nd(lua_State *l, struct lls_config *lls_conf)
{
	if (!ipv6_configured(lls_conf->net))
		return;
	list_lls(l, &lls_conf->nd_cache);
}

typedef void (*list_lls_fn)(lua_State *l, struct lls_config *lls_conf);

#define CTYPE_STRUCT_LLS_CONFIG_PTR "struct lls_config *"

static void
list_lls_for_lua(lua_State *l, list_lls_fn f)
{
	uint32_t ctypeid;
	uint32_t correct_ctypeid_lls_config = luaL_get_ctypeid(l,
		CTYPE_STRUCT_LLS_CONFIG_PTR);
	struct lls_config *lls_conf;

	/* First argument must be of type CTYPE_STRUCT_LLS_CONFIG_PTR. */
	void *cdata = luaL_checkcdata(l, 1,
		&ctypeid, CTYPE_STRUCT_LLS_CONFIG_PTR);
	if (ctypeid != correct_ctypeid_lls_config)
		luaL_error(l, "Expected `%s' as first argument",
			CTYPE_STRUCT_LLS_CONFIG_PTR);

	/* Second argument must be a Lua function. */
	luaL_checktype(l, 2, LUA_TFUNCTION);

	/* Third argument should be a Lua value. */
	if (lua_gettop(l) != 3)
		luaL_error(l, "Expected three arguments, however it got %d arguments",
			lua_gettop(l));

	lls_conf = *(struct lls_config **)cdata;

	f(l, lls_conf);

	lua_remove(l, 1);
	lua_remove(l, 1);
}

int
l_list_lls_arp(lua_State *l)
{
	list_lls_for_lua(l, list_arp);
	return 1;
}

int
l_list_lls_nd(lua_State *l)
{
	list_lls_for_lua(l, list_nd);
	return 1;
}

static int
process_pkts(struct lls_config *lls_conf, struct gatekeeper_if *iface,
	uint16_t rx_queue, uint16_t tx_queue, uint16_t max_pkt_burst)
{
	struct rte_mbuf *bufs[max_pkt_burst];
	uint16_t num_rx = rte_eth_rx_burst(iface->id, rx_queue, bufs,
		max_pkt_burst);
	int num_tx = 0;
	uint16_t i;

	for (i = 0; i < num_rx; i++) {
		struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(bufs[i],
			struct rte_ether_hdr *);
		void *next_hdr;
		uint16_t ether_type;

		/*
		 * The destination MAC address should be the broadcast
		 * address or match the interface's Ethernet address,
		 * because for round robin and LACP bonding the
		 * slave interfaces assume the MAC address of the
		 * bonded interface.
		 *
		 * See: http://dpdk.org/doc/guides/prog_guide/link_bonding_poll_mode_drv_lib.html#configuration
		 *
		 * XXX #74 Is this check needed? By default, the NIC only
		 * accepts the assigned MAC address, broadcast address,
		 * and any MAC added (for example, for IPv6 Ethernet multicast).
		 */
		if (unlikely(!rte_is_broadcast_ether_addr(&eth_hdr->d_addr) &&
			!rte_is_same_ether_addr(&eth_hdr->d_addr,
				&iface->eth_mc_addr) &&
			!rte_is_same_ether_addr(&eth_hdr->d_addr,
				&iface->ll_eth_mc_addr) &&
			!rte_is_same_ether_addr(&eth_hdr->d_addr,
				&iface->eth_addr)))
			goto free_buf;

		ether_type = rte_be_to_cpu_16(pkt_in_skip_l2(bufs[i], eth_hdr,
			&next_hdr));

		switch (ether_type) {
		case RTE_ETHER_TYPE_ARP:
			if (process_arp(lls_conf, iface, tx_queue,
					bufs[i], eth_hdr, next_hdr) == -1)
				goto free_buf;

			/* ARP reply was sent, so no free is needed. */
			num_tx++;
			continue;

			/*
			 * Both back and front interfaces cannot
			 * see ND packets received here.
			 * All ND packets come from the IPv6 filter.
			 */

		default:
			LLS_LOG(ERR, "%s interface should not be seeing a packet with EtherType 0x%04hx\n",
				iface->name, ether_type);
			goto free_buf;
		}
free_buf:
		rte_pktmbuf_free(bufs[i]);
	}

	return num_tx;
}

static int
lls_proc(void *arg)
{
	struct lls_config *lls_conf = (struct lls_config *)arg;
	struct net_config *net_conf = lls_conf->net;
	struct gatekeeper_if *front = &net_conf->front;
	struct gatekeeper_if *back = &net_conf->back;

	uint64_t prev_tsc = rte_rdtsc(), cur_tsc, diff_tsc;
	uint64_t timer_resolution_cycles =
		net_conf->rotate_log_interval_sec * cycles_per_sec;

	LLS_LOG(NOTICE, "The LLS block is running at lcore = %u\n",
		lls_conf->lcore_id);

	while (likely(!exiting)) {
		/* Read in packets on front and back interfaces. */
		int num_tx;

		if (lls_conf->rx_method_front & RX_METHOD_NIC) {
			num_tx = process_pkts(lls_conf, front,
				lls_conf->rx_queue_front,
				lls_conf->tx_queue_front,
				lls_conf->front_max_pkt_burst);
			if ((num_tx > 0) && lacp_enabled(net_conf, front)) {
				if (lacp_timer_reset(lls_conf, front) < 0)
					LLS_LOG(NOTICE, "Can't reset front LACP timer to skip cycle\n");
			}
		}

		if (net_conf->back_iface_enabled &&
				lls_conf->rx_method_back & RX_METHOD_NIC) {
			num_tx = process_pkts(lls_conf, back,
				lls_conf->rx_queue_back,
				lls_conf->tx_queue_back,
				lls_conf->back_max_pkt_burst);
			if ((num_tx > 0) && lacp_enabled(net_conf, back)) {
				if (lacp_timer_reset(lls_conf, back) < 0)
					LLS_LOG(NOTICE, "Can't reset back LACP timer to skip cycle\n");
			}
		}

		/*
		 * Process any requests. The RX method does not
		 * matter here, since the mailbox is always used
		 * for ARP/ND hold requests from other blocks.
		 */
		if (likely(lls_process_reqs(lls_conf) == 0)) {
			/*
			 * If there are no requests to go through, then do a
			 * scan of the cache (if enough time has passed).
			 *
			 * XXX #151 In theory, many new LLS changes could starve
			 * the ability to scan, but this will not likely
			 * happen. In fact, we may want to reduce the amount
			 * of times this is called, since reading the HPET
			 * timer is inefficient. See the timer application.
			 *
			 * Also invoke the TX burst function to fulfill
			 * the LACP requirement.
			 *
			 * XXX #151 The LACP requirement could be starved if
			 * the LLS block receives a lot of requests but
			 * we are unable to answer them -- i.e. the
			 * number of requests > 0 for a sustained
			 * period but we never invoke the TX burst.
			 */
			rte_timer_manage();

			prev_tsc = rte_rdtsc();
			continue;
		}

		cur_tsc = rte_rdtsc();
		diff_tsc = cur_tsc - prev_tsc;
		if (diff_tsc >= timer_resolution_cycles) {
			rte_timer_manage();
			prev_tsc = cur_tsc;
		}
	}

	LLS_LOG(NOTICE, "The LLS block at lcore = %u is exiting\n",
		lls_conf->lcore_id);

	return cleanup_lls();
}

static int
register_icmp_filter(struct gatekeeper_if *iface, uint16_t rx_queue,
	uint8_t *rx_method)
{
	int ret = ipv4_pkt_filter_add(iface,
		iface->ip4_addr.s_addr,
		0, 0, 0, 0,
		IPPROTO_ICMP, rx_queue,
		submit_icmp, match_icmp,
		rx_method);
	if (ret < 0) {
		LLS_LOG(ERR,
			"Could not add IPv4 ICMP filter on %s iface\n",
			iface->name);
		return ret;
	}
	return 0;
}

static int
register_icmp6_filters(struct gatekeeper_if *iface, uint16_t rx_queue,
	uint8_t *rx_method)
{
	/* All of the IPv6 addresses that a Gatekeeper interface supports. */
	const struct in6_addr *ip6_addrs[] = {
		&iface->ip6_addr,
		&iface->ll_ip6_addr,
		&iface->ip6_mc_addr,
		&iface->ll_ip6_mc_addr,
		/*
		 * The all nodes multicast address is only used to ignore
		 * router solitication/advertisement messages so that they
		 * do not clutter the Gatekeeper log.
		 */
		&ip6_allnodes_mc_addr,
	};
	unsigned int i;
	int ret;

	for (i = 0; i < RTE_DIM(ip6_addrs); i++) {
		ret = ipv6_pkt_filter_add(iface,
			(rte_be32_t *)&ip6_addrs[i]->s6_addr,
			0, 0, 0, 0,
			IPPROTO_ICMPV6, rx_queue,
			submit_icmp6, match_icmp6,
			rx_method);
		if (ret < 0) {
			LLS_LOG(ERR,
				"Could not add IPv6 ICMP filter on %s iface\n",
				iface->name);
			return ret;
		}
	}

	return 0;
}

static int
assign_lls_queue_ids(struct lls_config *lls_conf)
{
	int ret;
	/*
	 * Take the packets created for processing requests
	 * from mailbox as well as ARP and ND cache tables scan.
	 */
	unsigned int total_pkt_burst = lls_conf->total_pkt_burst +
		lls_conf->mailbox_burst_size + 2 *
		lls_conf->max_num_cache_records;
	unsigned int num_mbuf;

	/* The front NIC doesn't have hardware support. */
	if (!lls_conf->net->front.rss)
		total_pkt_burst -= lls_conf->front_max_pkt_burst;

	/* The back NIC is enabled and doesn't have hardware support. */
	if (lls_conf->net->back_iface_enabled && !lls_conf->net->back.rss)
		total_pkt_burst -= lls_conf->back_max_pkt_burst;

	num_mbuf = calculate_mempool_config_para("lls",
		lls_conf->net, total_pkt_burst);
	lls_conf->mp = create_pktmbuf_pool("lls",
		lls_conf->lcore_id, num_mbuf);
	if (lls_conf->mp == NULL) {
		ret = -1;
		goto fail;
	}

	/*
	 * LLS should only get its own RX queue if RSS is enabled,
	 * even if EtherType filter is not enabled.
	 *
	 * If RSS is disabled, then the network configuration can
	 * tell that it should ignore all other blocks' requests
	 * for queues and just allocate one RX queue.
	 *
	 * If RSS is enabled, then LLS has already informed the
	 * network configuration that it will be using a queue.
	 * The network configuration will crash if LLS doesn't
	 * configure that queue, so it still should, even if
	 * EtherType filter is not supported and LLS will not use it.
	 */

	if (lls_conf->net->front.rss) {
		ret = get_queue_id(&lls_conf->net->front, QUEUE_TYPE_RX,
			lls_conf->lcore_id, lls_conf->mp);
		if (ret < 0)
			goto fail;
		lls_conf->rx_queue_front = ret;
	}

	ret = get_queue_id(&lls_conf->net->front, QUEUE_TYPE_TX,
		lls_conf->lcore_id, NULL);
	if (ret < 0)
		goto fail;
	lls_conf->tx_queue_front = ret;

	if (lls_conf->net->back_iface_enabled) {
		if (lls_conf->net->back.rss) {
			ret = get_queue_id(&lls_conf->net->back, QUEUE_TYPE_RX,
				lls_conf->lcore_id, lls_conf->mp);
			if (ret < 0)
				goto fail;
			lls_conf->rx_queue_back = ret;
		}

		ret = get_queue_id(&lls_conf->net->back, QUEUE_TYPE_TX,
			lls_conf->lcore_id, NULL);
		if (ret < 0)
			goto fail;
		lls_conf->tx_queue_back = ret;
	}

	return 0;

fail:
	LLS_LOG(ERR, "Cannot assign queues\n");
	return ret;
}

static int
lls_stage1(void *arg)
{
	struct lls_config *lls_conf = arg;
	int ele_size = RTE_MAX(sizeof(struct lls_request),
		RTE_MAX(ARP_REQ_SIZE(lls_conf->mailbox_max_pkt_sub),
		RTE_MAX(ICMP_REQ_SIZE(lls_conf->mailbox_max_pkt_sub),
			ICMP6_REQ_SIZE(lls_conf->mailbox_max_pkt_sub))));
	int ret = assign_lls_queue_ids(lls_conf);
	if (ret < 0)
		return ret;

	/*
	 * Since run_lls() in lua/lls.lua will be called before lua/gk.lua
	 * or lua/gt.lua, if we put init_mailbox() in run_lls(), then we have
	 * already initialized LLS' mailbox with the initial
	 * lls_conf.mailbox_max_pkt_sub specified in lua/lls.lua, even if we
	 * change the value of lls_conf.mailbox_max_pkt_sub in lua/gk.lua or
	 * lua/gt.lua, it won't change the size of the entries in LLS mailbox.
	 *
	 * To initialize the LLS mailbox only after we get the final
	 * configuration by considering GK or GT blocks, we initialize
	 * LLS mailbox here.
	 */
	return init_mailbox("lls_req", lls_conf->mailbox_max_entries_exp,
		ele_size, lls_conf->mailbox_mem_cache_size,
		lls_conf->lcore_id, &lls_conf->requests);
}

static int
lls_stage2(void *arg)
{
	struct lls_config *lls_conf = arg;
	struct net_config *net_conf = lls_conf->net;
	int ret;

	if (lls_conf->arp_cache.iface_enabled(net_conf, &net_conf->front)) {
		if (hw_filter_eth_available(&net_conf->front)) {
			ret = ethertype_filter_add(&net_conf->front,
				RTE_ETHER_TYPE_ARP, lls_conf->rx_queue_front);
			if (ret < 0)
				return ret;
			lls_conf->rx_method_front |= RX_METHOD_NIC;
		} else if (lls_conf->rx_queue_front != 0) {
			/*
			 * RSS on most NICs seem to default to sending ARP
			 * (and other non-IP packets) to queue 0, so the LLS
			 * block should be listening on queue 0.
			 *
			 * On the Elastic Network Adapter (ENA) on Amazon,
			 * non-IP packets seem to be given to the first
			 * queue configured for RSS. Therefore, LLS does not
			 * need to run on queue 0 in that case, but there's
			 * no easy way of deciding whether it is needed
			 * at runtime.
			 */
			LLS_LOG(ERR, "If EtherType filters are not supported, the LLS block needs to listen on queue 0 on the front iface\n");
			return -1;
		}

		ret = register_icmp_filter(&net_conf->front,
			lls_conf->rx_queue_front,
			&lls_conf->rx_method_front);
		if (ret < 0)
			return ret;
	}

	if (lls_conf->arp_cache.iface_enabled(net_conf, &net_conf->back)) {
		if (hw_filter_eth_available(&net_conf->back)) {
			ret = ethertype_filter_add(&net_conf->back,
				RTE_ETHER_TYPE_ARP, lls_conf->rx_queue_back);
			if (ret < 0)
				return ret;
			lls_conf->rx_method_back |= RX_METHOD_NIC;
		} else if (lls_conf->rx_queue_back != 0) {
			/* See comment above about LLS listening on queue 0. */
			LLS_LOG(ERR, "If EtherType filters are not supported, the LLS block needs to listen on queue 0 on the back iface\n");
			return -1;
		}

		ret = register_icmp_filter(&net_conf->back,
			lls_conf->rx_queue_back,
			&lls_conf->rx_method_back);
		if (ret < 0)
			return ret;
	}

	if (lls_conf->nd_cache.iface_enabled(net_conf, &net_conf->front)) {
		ret = register_icmp6_filters(&net_conf->front,
			lls_conf->rx_queue_front,
			&lls_conf->rx_method_front);
		if (ret < 0)
			return ret;
	}

	if (lls_conf->nd_cache.iface_enabled(net_conf, &net_conf->back)) {
		ret = register_icmp6_filters(&net_conf->back,
			lls_conf->rx_queue_back,
			&lls_conf->rx_method_back);
		if (ret < 0)
			return ret;
	}

	return 0;
}

int
run_lls(struct net_config *net_conf, struct lls_config *lls_conf)
{
	int ret;
	uint16_t front_inc, back_inc = 0;

	if (net_conf == NULL || lls_conf == NULL) {
		ret = -1;
		goto out;
	}

	lls_logtype = rte_log_register("gatekeeper.lls");
	if (lls_logtype < 0) {
		ret = -1;
		goto out;
	}
	ret = rte_log_set_level(lls_logtype, lls_conf->log_level);
	if (ret < 0) {
		ret = -1;
		goto out;
	}
	lls_conf->log_type = lls_logtype;

	log_ratelimit_state_init(lls_conf->lcore_id,
		lls_conf->log_ratelimit_interval_ms,
		lls_conf->log_ratelimit_burst);

	tb_ratelimit_state_init(&lls_conf->front_icmp_rs,
		lls_conf->front_icmp_msgs_per_sec,
		lls_conf->front_icmp_msgs_burst);
	tb_ratelimit_state_init(&lls_conf->back_icmp_rs,
		lls_conf->back_icmp_msgs_per_sec,
		lls_conf->back_icmp_msgs_burst);

	if (!(lls_conf->front_max_pkt_burst > 0 &&
			(net_conf->back_iface_enabled == 0 ||
			(net_conf->back_iface_enabled &&
			lls_conf->back_max_pkt_burst > 0)))) {
		ret = -1;
		goto out;
	}

	front_inc = lls_conf->front_max_pkt_burst;
	net_conf->front.total_pkt_burst += front_inc;
	if (net_conf->back_iface_enabled) {
		back_inc = lls_conf->back_max_pkt_burst;
		net_conf->back.total_pkt_burst += back_inc;
	}
	lls_conf->total_pkt_burst = front_inc + back_inc;

	ret = net_launch_at_stage1(net_conf, 1, 1, 1, 1, lls_stage1, lls_conf);
	if (ret < 0)
		goto burst;

	ret = launch_at_stage2(lls_stage2, lls_conf);
	if (ret < 0)
		goto stage1;

	ret = launch_at_stage3("lls", lls_proc, lls_conf, lls_conf->lcore_id);
	if (ret < 0)
		goto stage2;

	/*
	 * Do LLS cache scan every @lls_conf->cache_scan_interval_sec
	 * seconds.
	 */
	rte_timer_init(&lls_conf->scan_timer);
	ret = rte_timer_reset(&lls_conf->scan_timer,
		lls_conf->cache_scan_interval_sec * rte_get_timer_hz(),
		PERIODICAL, lls_conf->lcore_id, lls_scan, lls_conf);
	if (ret < 0) {
		LLS_LOG(ERR, "Cannot set LLS scan timer\n");
		goto stage3;
	}

	/* Rotate log file every rotate_log_interval_sec seconds. */
	rte_timer_init(&lls_conf->log_timer);
	ret = rte_timer_reset(&lls_conf->log_timer,
		net_conf->rotate_log_interval_sec * rte_get_timer_hz(),
		PERIODICAL, lls_conf->lcore_id, rotate_log, NULL);
	if (ret < 0) {
		LLS_LOG(ERR, "Cannot set Gatekeeper log timer\n");
		goto scan_timer;
	}

	lls_conf->net = net_conf;
	if (arp_enabled(lls_conf)) {
		ret = lls_cache_init(lls_conf, &lls_conf->arp_cache,
			sizeof(struct in_addr));
		if (ret < 0) {
			LLS_LOG(ERR, "ARP cache cannot be started\n");
			goto log_timer;
		}

		/* Set timeouts for front and back (if needed). */
		if (lls_conf->arp_cache.iface_enabled(net_conf,
				&net_conf->front))
			lls_conf->arp_cache.front_timeout_sec =
				net_conf->front.arp_cache_timeout_sec;
		if (lls_conf->arp_cache.iface_enabled(net_conf,
				&net_conf->back))
			lls_conf->arp_cache.back_timeout_sec =
				lls_conf->net->back.arp_cache_timeout_sec;
	}

	if (nd_enabled(lls_conf)) {
		ret = lls_cache_init(lls_conf, &lls_conf->nd_cache,
			sizeof(struct in6_addr));
		if (ret < 0) {
			LLS_LOG(ERR, "ND cache cannot be started\n");
			goto arp;
		}

		/* Set timeouts for front and back (if needed). */
		if (lls_conf->nd_cache.iface_enabled(net_conf,
				&net_conf->front))
			lls_conf->nd_cache.front_timeout_sec =
				net_conf->front.nd_cache_timeout_sec;
		if (lls_conf->nd_cache.iface_enabled(net_conf, &net_conf->back))
			lls_conf->nd_cache.back_timeout_sec =
				lls_conf->net->back.nd_cache_timeout_sec;
	}

	/* Set per-interface LACP timers, if needed. */
	if (lacp_enabled(net_conf, &net_conf->front)) {
		rte_timer_init(&net_conf->front.lacp_timer);
		ret = lacp_timer_reset(lls_conf, &net_conf->front);
		if (ret < 0) {
			LLS_LOG(ERR,
				"Cannot set LACP timer on front interface\n");
			goto nd;
		}
	}
	if (lacp_enabled(net_conf, &net_conf->back)) {
		rte_timer_init(&net_conf->back.lacp_timer);
		ret = lacp_timer_reset(lls_conf, &net_conf->back);
		if (ret < 0) {
			LLS_LOG(ERR,
				"Cannot set LACP timer on back interface\n");
			goto lacp;
		}
	}

	return 0;
lacp:
	if (lacp_enabled(net_conf, &net_conf->front))
		rte_timer_stop(&net_conf->front.lacp_timer);
nd:
	if (nd_enabled(lls_conf))
		lls_cache_destroy(&lls_conf->nd_cache);
arp:
	if (arp_enabled(lls_conf))
		lls_cache_destroy(&lls_conf->arp_cache);
log_timer:
	rte_timer_stop(&lls_conf->log_timer);
scan_timer:
	rte_timer_stop(&lls_conf->scan_timer);
stage3:
	pop_n_at_stage3(1);
stage2:
	pop_n_at_stage2(1);
stage1:
	pop_n_at_stage1(1);
burst:
	net_conf->front.total_pkt_burst -= front_inc;
	net_conf->back.total_pkt_burst -= back_inc;
out:
	return ret;
}
