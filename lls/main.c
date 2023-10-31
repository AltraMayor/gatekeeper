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

#include <stdbool.h>
#include <unistd.h>
#include <arpa/inet.h>

#include <rte_cycles.h>
#include <rte_ethdev.h>
#include <rte_icmp.h>

#include "gatekeeper_cps.h"
#include "gatekeeper_config.h"
#include "gatekeeper_l2.h"
#include "gatekeeper_launch.h"
#include "gatekeeper_lls.h"
#include "gatekeeper_varip.h"
#include "gatekeeper_absflow.h"
#include "arp.h"
#include "cache.h"
#include "nd.h"

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
	struct lls_request *req;

	if (unlikely(!arp_enabled(&lls_conf))) {
		G_LOG(ERR, "%s(lcore=%u): ARP service is not enabled\n",
			__func__, lcore_id);
		return -ENOTSUP;
	}

	req = mb_alloc_entry(&lls_conf.requests);
	if (unlikely(req == NULL))
		return -ENOENT;

	*req = (typeof(*req)) {
		.ty = LLS_REQ_HOLD,
		.u.hold = {
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
		},
	};

	return mb_send_entry(&lls_conf.requests, req);
}

int
put_arp(struct in_addr *ipv4, unsigned int lcore_id)
{
	struct lls_request *req;

	if (unlikely(!arp_enabled(&lls_conf))) {
		G_LOG(ERR, "%s(lcore=%u): ARP service is not enabled\n",
			__func__, lcore_id);
		return -ENOTSUP;
	}

	req = mb_alloc_entry(&lls_conf.requests);
	if (unlikely(req == NULL))
		return -ENOENT;

	*req = (typeof(*req)) {
		.ty = LLS_REQ_PUT,
		.u.put = {
			.cache = &lls_conf.arp_cache,
			.addr = {
				.proto = RTE_ETHER_TYPE_IPV4,
				.ip.v4 = *ipv4,
			},
			.lcore_id = lcore_id,
		},
	};

	return mb_send_entry(&lls_conf.requests, req);
}

int
hold_nd(lls_req_cb cb, void *arg, struct in6_addr *ipv6, unsigned int lcore_id)
{
	struct lls_request *req;

	if (unlikely(!nd_enabled(&lls_conf))) {
		G_LOG(ERR, "%s(lcore=%u): ND service is not enabled\n",
			__func__, lcore_id);
		return -ENOTSUP;
	}

	req = mb_alloc_entry(&lls_conf.requests);
	if (unlikely(req == NULL))
		return -ENOENT;

	*req = (typeof(*req)) {
		.ty = LLS_REQ_HOLD,
		.u.hold = {
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
		},
	};

	return mb_send_entry(&lls_conf.requests, req);
}

int
put_nd(struct in6_addr *ipv6, unsigned int lcore_id)
{
	struct lls_request *req;

	if (unlikely(!nd_enabled(&lls_conf))) {
		G_LOG(ERR, "%s(lcore=%u): ND service is not enabled\n",
			__func__, lcore_id);
		return -ENOTSUP;
	}

	req = mb_alloc_entry(&lls_conf.requests);
	if (unlikely(req == NULL))
		return -ENOENT;

	*req = (typeof(*req)) {
		.ty = LLS_REQ_PUT,
		.u.put = {
			.cache = &lls_conf.nd_cache,
			.addr = {
				.proto = RTE_ETHER_TYPE_IPV6,
				.ip.v6 = *ipv6,
			},
			.lcore_id = lcore_id,
		},
	};

	return mb_send_entry(&lls_conf.requests, req);
}

/* Submit packets to the LLS block when hardware filtering is not available. */
static void
submit_packets(struct absflow_packet **infos, uint16_t n,
	struct gatekeeper_if *iface, void *director_arg)
{
	struct lls_request *req;
	unsigned int i;
	int ret;

	RTE_SET_USED(director_arg);

	if (unlikely(n > lls_conf.mailbox_max_pkt_sub)) {
		G_LOG(ERR, "%s(): too many packets: n=%u > lls_conf.mailbox_max_pkt_sub=%u\n",
			__func__, n, lls_conf.mailbox_max_pkt_sub);
		goto free_infos;
	}

	req = mb_alloc_entry(&lls_conf.requests);
	if (unlikely(req == NULL))
		goto free_infos;

	*req = (typeof(*req)) {
		.ty = LLS_REQ_PACKETS,
		.u.packets = {
			.num_pkts = n,
			.iface = iface,
		},
	};
	for (i = 0; i < n; i++)
		absflow_copy_info(&req->u.packets.infos[i], infos[i]);

	ret = mb_send_entry(&lls_conf.requests, req);
	if (unlikely(ret < 0))
		goto free_infos;
	return;

free_infos:
	absflow_free_packets(infos, n);
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
list_lls(lua_State *L, struct lls_cache *cache)
{
	uint32_t next = 0;
	const void *key;
	void *data;
	int32_t index;
	void *cdata;
	uint32_t correct_ctypeid_lls_dentry = luaL_get_ctypeid(L,
		CTYPE_STRUCT_LLS_DUMP_ENTRY_PTR);

	index = rte_hash_iterate(cache->hash, (void *)&key, &data, &next);
	while (index >= 0) {
		struct lls_dump_entry dentry;
		struct lls_record *record = &cache->records[index];

		fillup_lls_dump_entry(&dentry, &record->map);

		lua_pushvalue(L, 2);
		lua_insert(L, 3);
		cdata = luaL_pushcdata(L, correct_ctypeid_lls_dentry,
			sizeof(struct lls_dump_entry *));
		*(struct lls_dump_entry **)cdata = &dentry;
		lua_insert(L, 4);

		lua_call(L, 2, 1);

		index = rte_hash_iterate(cache->hash,
			(void *)&key, &data, &next);
	}
}

static void
list_arp(lua_State *L, struct lls_config *lls_conf)
{
	if (!ipv4_configured(lls_conf->net))
		return;
	list_lls(L, &lls_conf->arp_cache);
}

static void
list_nd(lua_State *L, struct lls_config *lls_conf)
{
	if (!ipv6_configured(lls_conf->net))
		return;
	list_lls(L, &lls_conf->nd_cache);
}

typedef void (*list_lls_fn)(lua_State *L, struct lls_config *lls_conf);

#define CTYPE_STRUCT_LLS_CONFIG_PTR "struct lls_config *"

static void
list_lls_for_lua(lua_State *L, list_lls_fn f)
{
	uint32_t ctypeid;
	uint32_t correct_ctypeid_lls_config = luaL_get_ctypeid(L,
		CTYPE_STRUCT_LLS_CONFIG_PTR);
	struct lls_config *lls_conf;

	/* First argument must be of type CTYPE_STRUCT_LLS_CONFIG_PTR. */
	void *cdata = luaL_checkcdata(L, 1,
		&ctypeid, CTYPE_STRUCT_LLS_CONFIG_PTR);
	if (ctypeid != correct_ctypeid_lls_config)
		luaL_error(L, "Expected `%s' as first argument",
			CTYPE_STRUCT_LLS_CONFIG_PTR);

	/* Second argument must be a Lua function. */
	luaL_checktype(L, 2, LUA_TFUNCTION);

	/* Third argument should be a Lua value. */
	if (lua_gettop(L) != 3)
		luaL_error(L, "Expected three arguments, however it got %d arguments",
			lua_gettop(L));

	lls_conf = *(struct lls_config **)cdata;

	f(L, lls_conf);

	lua_remove(L, 1);
	lua_remove(L, 1);
}

int
l_list_lls_arp(lua_State *L)
{
	list_lls_for_lua(L, list_arp);
	return 1;
}

int
l_list_lls_nd(lua_State *L)
{
	list_lls_for_lua(L, list_nd);
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
			/*
			 * The log level of the following log entry cannot be
			 * ERR because NICs typically send unmatched patckets
			 * to queue 0, which the LLS block often serves.
			 *
			 * The log level cannot be WARNING either because
			 * Gatekeeper servers have to tolerate unwanted
			 * traffic at some vantage points and LLS blocks
			 * typically run at WARNING level.
			 */
			G_LOG(NOTICE, "%s interface should not be seeing a packet with EtherType 0x%04hx\n",
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

	G_LOG(NOTICE, "The LLS block is running at tid = %u\n", gettid());

	if (needed_caps(0, NULL) < 0) {
		G_LOG(ERR, "Could not set needed capabilities\n");
		exiting = true;
	}

	while (likely(!exiting)) {
		/* Read packets from front and back interfaces. */
		int num_tx = process_pkts(lls_conf, front,
			lls_conf->rx_queue_front,
			lls_conf->tx_queue_front,
			lls_conf->front_max_pkt_burst);
		if ((num_tx > 0) && lacp_enabled(net_conf, front)) {
			if (lacp_timer_reset(lls_conf, front) < 0)
				G_LOG(NOTICE, "Can't reset front LACP timer to skip cycle\n");
		}

		if (net_conf->back_iface_enabled) {
			num_tx = process_pkts(lls_conf, back,
				lls_conf->rx_queue_back,
				lls_conf->tx_queue_back,
				lls_conf->back_max_pkt_burst);
			if ((num_tx > 0) && lacp_enabled(net_conf, back)) {
				if (lacp_timer_reset(lls_conf, back) < 0)
					G_LOG(NOTICE, "Can't reset back LACP timer to skip cycle\n");
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

	G_LOG(NOTICE, "The LLS block is exiting\n");

	return cleanup_lls();
}

static void
submit_icmp_packets(struct rte_mbuf **pkts, unsigned int num_pkts,
	struct gatekeeper_if *iface, struct lls_config *lls_conf)
{
	struct token_bucket_ratelimit_state *rs =
		iface == &lls_conf->net->front
			? &lls_conf->front_icmp_rs
			: &lls_conf->back_icmp_rs;
	unsigned int num_granted_pkts = tb_ratelimit_allow_n(num_pkts, rs);

	cps_submit_direct(pkts, num_granted_pkts, iface);

	rte_pktmbuf_free_bulk(&pkts[num_granted_pkts],
		num_pkts - num_granted_pkts);
}

static void
process_icmpv4_pkts(struct absflow_packet **infos, uint16_t n,
	struct gatekeeper_if *iface, void *director_arg)
{
	struct rte_mbuf *kni_pkts[n];
	unsigned int num_kni_pkts = 0;
	int i;

	for (i = 0; i < n; i++) {
		struct absflow_packet *info = infos[i];
		struct rte_icmp_hdr *icmpv4_hdr = info->l4_hdr;

		if (unlikely(icmpv4_hdr->icmp_type == ICMP_DEST_UNREACHABLE_TYPE
				&&
				icmpv4_hdr->icmp_code == ICMP_FRAG_REQ_DF_CODE)
				) {
			struct rte_ipv4_hdr *ipv4_hdr = info->l3_hdr;
			char src_ip_buf[INET_ADDRSTRLEN];
			const char *src_ip_or_err = inet_ntop(AF_INET,
				&ipv4_hdr->src_addr,
				src_ip_buf, sizeof(src_ip_buf));
			if (unlikely(src_ip_or_err == NULL)) {
				src_ip_or_err =
					"(could not convert IP to string)";
			}
			G_LOG(ERR, "%s(%s): received \"Fragmentation required, and DF flag set\" ICMPv4 packet from source address %s; check MTU along path\n",
				__func__, iface->name, src_ip_or_err);
		}

		kni_pkts[num_kni_pkts++] = info->pkt;
	}

	if (likely(num_kni_pkts > 0)) {
		struct lls_config *lls_conf = director_arg;
		submit_icmp_packets(kni_pkts, num_kni_pkts, iface, lls_conf);
	}
}

static int
register_icmpv4_filter(struct gatekeeper_if *iface, uint16_t rx_queue,
	struct absflow_execution *exec)
{
	uint32_t flow_id;
	int ret = absflow_add_ipv4_filter(iface, iface->ip4_addr.s_addr,
		0, 0, 0, 0, IPPROTO_ICMP, rx_queue, submit_packets, true);
	if (unlikely(ret < 0)) {
		G_LOG(ERR, "%s(%s): cannot add IPv4 ICMP filter (errno=%i): %s\n",
			__func__, iface->name, -ret, strerror(-ret));
		return ret;
	}
	flow_id = ret;

	ret = absflow_add_submit(exec, flow_id, process_icmpv4_pkts);
	if (unlikely(ret < 0)) {
		G_LOG(ERR, "%s(%s): cannot add submit (errno=%i): %s\n",
			__func__, iface->name, -ret, strerror(-ret));
		return ret;
	}

	return 0;
}

static void
process_icmpv6_pkts(struct absflow_packet **infos, uint16_t n,
	struct gatekeeper_if *iface, void *director_arg)
{
	struct lls_config *lls_conf = director_arg;
	struct rte_mbuf *free_pkts[n];
	struct rte_mbuf *kni_pkts[n];
	unsigned int num_free_pkts = 0;
	unsigned int num_kni_pkts = 0;
	int i;

	for (i = 0; i < n; i++) {
		struct absflow_packet *info = infos[i];
		struct icmpv6_hdr *icmpv6_hdr = info->l4_hdr;

		if (pkt_is_nd_neighbor(icmpv6_hdr->type, icmpv6_hdr->code)) {
			if (unlikely(process_nd(lls_conf, iface, info->pkt) < 0
					))
				free_pkts[num_free_pkts++] = info->pkt;
			continue;
		}

		if (unlikely(icmpv6_hdr->type == ICMPV6_PACKET_TOO_BIG_TYPE &&
				icmpv6_hdr->code == ICMPV6_PACKET_TOO_BIG_CODE)
				) {
			struct rte_ipv6_hdr *ipv6_hdr = info->l3_hdr;
			char src_ip_buf[INET6_ADDRSTRLEN];
			const char *src_ip_or_err = inet_ntop(AF_INET6,
				&ipv6_hdr->src_addr,
				src_ip_buf, sizeof(src_ip_buf));
			if (unlikely(src_ip_or_err == NULL)) {
				src_ip_or_err =
					"(could not convert IP to string)";
			}
			G_LOG(ERR, "%s(%s): received \"Packet Too Big\" ICMPv6 packet from source address %s; check MTU along path\n",
				__func__, iface->name, src_ip_or_err);
		}

		kni_pkts[num_kni_pkts++] = info->pkt;
	}

	if (unlikely(num_free_pkts > 0))
		rte_pktmbuf_free_bulk(free_pkts, num_free_pkts);
	if (likely(num_kni_pkts > 0))
		submit_icmp_packets(kni_pkts, num_kni_pkts, iface, lls_conf);
}

static int
register_icmpv6_filters(struct gatekeeper_if *iface, uint16_t rx_queue,
	struct absflow_execution *exec)
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

	for (i = 0; i < RTE_DIM(ip6_addrs); i++) {
		uint32_t flow_id;
		int ret = absflow_add_ipv6_filter(iface, ip6_addrs[i]->s6_addr,
			0, 0, 0, 0, IPPROTO_ICMPV6, rx_queue,
			submit_packets, true);
		if (unlikely(ret < 0)) {
			G_LOG(ERR, "%s(%s): cannot add IPv6 ICMP filter (errno=%i): %s\n",
				__func__, iface->name, -ret, strerror(-ret));
			return ret;
		}
		flow_id = ret;

		ret = absflow_add_submit(exec, flow_id, process_icmpv6_pkts);
		if (unlikely(ret < 0)) {
			G_LOG(ERR, "%s(%s): cannot add submit (errno=%i): %s\n",
				__func__, iface->name, -ret, strerror(-ret));
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
	G_LOG(ERR, "Cannot assign queues\n");
	return ret;
}

#define PACKETS_REQ_SIZE(num_pkts)					\
	(offsetof(struct lls_request, end_of_header) +			\
		sizeof(struct lls_packets_req) + 			\
		sizeof(struct absflow_packet) * num_pkts)

static int
lls_stage1(void *arg)
{
	struct lls_config *lls_conf = arg;
	int ele_size = RTE_MAX(sizeof(struct lls_request),
		PACKETS_REQ_SIZE(lls_conf->mailbox_max_pkt_sub));
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
		ret = absflow_add_ethertype_filter(&net_conf->front,
			RTE_ETHER_TYPE_ARP, lls_conf->rx_queue_front,
			submit_arp, true);
		if (ret < 0 && net_conf->front.rss &&
				lls_conf->rx_queue_front != 0) {
			/*
			 * If EtherType flows are not supported but RSS is,
			 * the LLS block should be listening on queue 0. This
			 * is because RSS on most NICs seems to default to
			 * sending ARP (and other non-IP packets) to queue 0.
			 * The LLS block can then simply discard any other
			 * non-ARP and non-IP packets that it receives.
			 *
			 * On the Elastic Network Adapter (ENA) on Amazon,
			 * non-IP packets seem to be given to the first
			 * queue configured for RSS. Therefore, LLS does not
			 * need to run on queue 0 in that case, but there's
			 * no easy way of detecting this case at runtime.
			 */
			G_LOG(ERR, "If EtherType filters are not supported, the LLS block needs to listen on queue 0 on the front iface\n");
			return -1;
		}
		if (ret >= 0) {
			const unsigned int flow_id = ret;
			/* TODO This function must move to lls_proc(). */
			ret = absflow_rx_method(&net_conf->front, &flow_id, 1,
				&lls_conf->rx_method_front);
			/* ARP packets can be received from the NIC. */
			lls_conf->rx_method_front |= RX_METHOD_NIC;
		} else {
			/*
			 * EtherType flows cannot be used, perhaps because
			 * they are not supported by hardware, RSS is not
			 * supported by hardware, or the particular protocol
			 * (ARP) is not permitted. In this case, ARP packets
			 * will be received via mailboxes.
			 */
			lls_conf->rx_method_front |= RX_METHOD_MB;
		}

		ret = register_icmpv4_filter(&net_conf->front,
			lls_conf->rx_queue_front, &lls_conf->front_exec);
		if (unlikely(ret < 0))
			return ret;
	}

	if (lls_conf->arp_cache.iface_enabled(net_conf, &net_conf->back)) {
		/* See comments above about return values. */
		ret = absflow_add_ethertype(&net_conf->back,
			RTE_ETHER_TYPE_ARP, lls_conf->rx_queue_back,
			submit_arp, true);
		if (ret < 0 && net_conf->back.rss &&
				lls_conf->rx_queue_back != 0) {
			G_LOG(ERR, "If EtherType flows are not supported, the LLS block must listen on queue 0 on the back iface\n");
			return -1;
		}
		if (ret >= 0) {
			/* TODO This function must move to lls_proc(). */
			/* ARP packets can be received from the NIC. */
			lls_conf->rx_method_back |= RX_METHOD_NIC;
		} else {
			/* ARP packets will be received via mailboxes. */
			lls_conf->rx_method_back |= RX_METHOD_MB;
		}

		ret = register_icmpv4_filter(&net_conf->back,
			lls_conf->rx_queue_back, &lls_conf->back_exec);
		if (unlikely(ret < 0))
			return ret;
	}

	if (lls_conf->nd_cache.iface_enabled(net_conf, &net_conf->front)) {
		ret = register_icmpv6_filters(&net_conf->front,
			lls_conf->rx_queue_front, &lls_conf->front_exec);
		if (unlikely(ret < 0))
			return ret;
	}

	if (lls_conf->nd_cache.iface_enabled(net_conf, &net_conf->back)) {
		ret = register_icmpv6_filters(&net_conf->back,
			lls_conf->rx_queue_back, &lls_conf->back_exec);
		if (unlikely(ret < 0))
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

	log_ratelimit_state_init(lls_conf->lcore_id,
		lls_conf->log_ratelimit_interval_ms,
		lls_conf->log_ratelimit_burst,
		lls_conf->log_level, "LLS");

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
		G_LOG(ERR, "Cannot set LLS scan timer\n");
		goto stage3;
	}

	/* Rotate log file every rotate_log_interval_sec seconds. */
	rte_timer_init(&lls_conf->log_timer);
	ret = rte_timer_reset(&lls_conf->log_timer,
		net_conf->rotate_log_interval_sec * rte_get_timer_hz(),
		PERIODICAL, lls_conf->lcore_id, rotate_log, NULL);
	if (ret < 0) {
		G_LOG(ERR, "Cannot set Gatekeeper log timer\n");
		goto scan_timer;
	}

	lls_conf->net = net_conf;
	if (arp_enabled(lls_conf)) {
		ret = lls_cache_init(lls_conf, &lls_conf->arp_cache,
			sizeof(struct in_addr));
		if (ret < 0) {
			G_LOG(ERR, "ARP cache cannot be started\n");
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
			G_LOG(ERR, "ND cache cannot be started\n");
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
			G_LOG(ERR,
				"Cannot set LACP timer on front interface\n");
			goto nd;
		}
	}
	if (lacp_enabled(net_conf, &net_conf->back)) {
		rte_timer_init(&net_conf->back.lacp_timer);
		ret = lacp_timer_reset(lls_conf, &net_conf->back);
		if (ret < 0) {
			G_LOG(ERR,
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
