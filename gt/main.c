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

#include <rte_log.h>
#include <rte_ether.h>
#include <rte_lcore.h>
#include <rte_malloc.h>

#include "gatekeeper_ggu.h"
#include "gatekeeper_ipip.h"
#include "gatekeeper_gk.h"
#include "gatekeeper_gt.h"
#include "gatekeeper_main.h"
#include "gatekeeper_net.h"
#include "gatekeeper_launch.h"

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
	uint16_t parsed_len = sizeof(struct ether_hdr);
	struct ether_hdr *eth_hdr = rte_pktmbuf_mtod(pkt, struct ether_hdr *);
	struct ipv4_hdr *outer_ipv4_hdr = NULL;
	struct ipv6_hdr *outer_ipv6_hdr = NULL;
	struct ipv4_hdr *inner_ipv4_hdr = NULL;
	struct ipv6_hdr *inner_ipv6_hdr = NULL;

	info->l2_hdr = eth_hdr;
	info->outer_ip_ver = rte_be_to_cpu_16(eth_hdr->ether_type);
	info->outer_l3_hdr = &eth_hdr[1];

	switch (info->outer_ip_ver) {
	case ETHER_TYPE_IPv4:
		if (pkt->data_len < parsed_len + sizeof(struct ipv4_hdr))
			return -1;

		outer_ipv4_hdr = (struct ipv4_hdr *)info->outer_l3_hdr;
		parsed_len += sizeof(struct ipv4_hdr);
		info->priority = (outer_ipv4_hdr->type_of_service >> 2);
		encasulated_proto = outer_ipv4_hdr->next_proto_id;
		break;
	case ETHER_TYPE_IPv6:
		if (pkt->data_len < parsed_len + sizeof(struct ipv6_hdr))
			return -1;

		outer_ipv6_hdr = (struct ipv6_hdr *)info->outer_l3_hdr;
		parsed_len += sizeof(struct ipv6_hdr);
		info->priority = (((outer_ipv6_hdr->vtc_flow >> 20)
			& 0xFF) >> 2);
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
	return likely((pkt_info->outer_ip_ver == ETHER_TYPE_IPv4 &&
			((struct ipv4_hdr *)
			pkt_info->outer_l3_hdr)->dst_addr
			== gt_conf->net->front.ip4_addr.s_addr)
			||
			(pkt_info->outer_ip_ver == ETHER_TYPE_IPv6 &&
			memcmp(((struct ipv6_hdr *)
			pkt_info->outer_l3_hdr)->dst_addr,
			gt_conf->net->front.ip6_addr.s6_addr,
			sizeof(gt_conf->net->front.ip6_addr) == 0)));
}

static void
print_ip_err_msg(struct gt_packet_headers *pkt_info)
{
	char src[128];
	char dst[128];

	if (pkt_info->outer_ip_ver == ETHER_TYPE_IPv4) {
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

static int
fill_eth_hdr(struct rte_mbuf *m,
	struct gt_config *gt_conf, struct gt_packet_headers *pkt_info)
{
	uint16_t outer_ip_len;
	struct ether_hdr *new_eth;

	if (pkt_info->outer_ip_ver == ETHER_TYPE_IPv4)
		outer_ip_len = sizeof(struct ipv4_hdr);
	else
		outer_ip_len = sizeof(struct ipv6_hdr);

	if (rte_pktmbuf_adj(m, outer_ip_len) == NULL)
		return -1;

	/*
	 * Fill up the Ethernet header, and forward
	 * the original packet to the destination.
	 */
	new_eth = rte_pktmbuf_mtod(m, struct ether_hdr *);
	ether_addr_copy(&gt_conf->net->front.eth_addr,
		&new_eth->s_addr);
	/*
	 * TODO The destination MAC address
	 * comes from LLS block.
	 */

	new_eth->ether_type =
		rte_cpu_to_be_16(pkt_info->inner_ip_ver);

	return 0;
}

static int
gt_proc(void *arg)
{
	unsigned int lcore = rte_lcore_id();
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
		struct rte_mbuf *rx_bufs[GATEKEEPER_MAX_PKT_BURST];
		struct rte_mbuf *tx_bufs[GATEKEEPER_MAX_PKT_BURST];

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

			/*
			 * Only request packets and priority packets
			 * with capabilities about to expire go through a
			 * policy decision.
			 *
			 * Other packets will be fowarded directly.
			 */
			ret = gt_parse_incoming_pkt(m, &pkt_info);
			if (ret < 0) {
				RTE_LOG(ALERT, GATEKEEPER,
					"gt: parsing an invalid packet!\n");
				rte_pktmbuf_free(m);
				continue;
			}

			if (!is_valid_dest_addr(gt_conf, &pkt_info)) {
				print_ip_err_msg(&pkt_info);
				rte_pktmbuf_free(m);
				continue;
			}

			if (pkt_info.priority <= 1) {
				ret = fill_eth_hdr(m, gt_conf, &pkt_info);
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

			if (policy.state == GK_GRANTED) {
				ret = fill_eth_hdr(m, gt_conf, &pkt_info);
				if (ret < 0)
					rte_pktmbuf_free(m);
				else
					tx_bufs[num_tx++] = m;
			} else
				rte_pktmbuf_free(m);

			/* TODO Reply the policy decision to GK-GT unit. */
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
		goto free_lua_state;
	}

	/* Run the loaded chunk. */
	ret = lua_pcall(instance->lua_state, 0, 0, 0);
	if (ret != 0) {
		RTE_LOG(ERR, GATEKEEPER,
			"gt: %s!\n", lua_tostring(instance->lua_state, -1));
		ret = -1;
		goto free_lua_state;
	}

	goto out;

free_lua_state:
	lua_close(instance->lua_state);
	instance->lua_state = NULL;
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
			goto out;
		}
		inst_ptr->rx_queue = ret;

		ret = get_queue_id(&gt_conf->net->front, QUEUE_TYPE_TX, lcore);
		if (ret < 0) {
			RTE_LOG(ERR, GATEKEEPER, "gt: cannot assign a TX queue for the front interface for lcore %u\n",
				lcore);
			goto out;
		}
		inst_ptr->tx_queue = ret;

		/*
		 * Set up the lua state for each instance,
		 * and initialize the policy tables.
		 */
		ret = config_gt_instance(gt_conf, lcore);
		if (ret < 0)
			goto free_lua_state;

		num_succ_instances++;
	}

	ret = 0;
	goto out;

free_lua_state:
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
		goto  instance;

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
	return gt_setup_rss(gt_conf);
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
