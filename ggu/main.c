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

#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_log.h>
#include <rte_lcore.h>
#include <rte_malloc.h>
#include <rte_ethdev.h>
#include <rte_atomic.h>

#include "gatekeeper_ggu.h"
#include "gatekeeper_gk.h"
#include "gatekeeper_net.h"
#include "gatekeeper_main.h"
#include "gatekeeper_config.h"
#include "gatekeeper_launch.h"
#include "gatekeeper_varip.h"

static void
process_single_policy(const struct ggu_policy *policy, const struct ggu_config *ggu_conf)
{
	struct gk_cmd_entry *entry;
	/*
	 * Obtain mailbox of that GK block,
	 * and send the policy decision to the GK block.
	 */
	struct mailbox *mb =
		get_responsible_gk_mailbox(&policy->flow, ggu_conf->gk);

	if (mb == NULL)
		return;

	entry = mb_alloc_entry(mb);
	if (entry == NULL)
		return;

	entry->op = GGU_POLICY_ADD;
	entry->u.ggu.state = policy->state;
	rte_memcpy(&entry->u.ggu.flow, &policy->flow, sizeof(entry->u.ggu.flow));

	switch(policy->state) {
	case GK_GRANTED:
		entry->u.ggu.params.u.granted.tx_rate_kb_sec =
			rte_be_to_cpu_32(
			policy->params.u.granted.tx_rate_kb_sec);
		entry->u.ggu.params.u.granted.cap_expire_sec =
			rte_be_to_cpu_32(
			policy->params.u.granted.cap_expire_sec);
		entry->u.ggu.params.u.granted.next_renewal_ms =
			rte_be_to_cpu_32(
			policy->params.u.granted.next_renewal_ms);
		entry->u.ggu.params.u.granted.renewal_step_ms =
			rte_be_to_cpu_32(
			policy->params.u.granted.renewal_step_ms);
		break;

	case GK_DECLINED:
		entry->u.ggu.params.u.declined.expire_sec =
			rte_be_to_cpu_32(policy->params.u.declined.expire_sec);
		break;

	default:
		RTE_LOG(ERR, GATEKEEPER, "ggu: impossible policy state %hhu\n",
			policy->state);
		mb_free_entry(mb, entry);
		return;
	}

	mb_send_entry(mb, entry);
}

static inline uint8_t
ipv4_hdr_len(struct ipv4_hdr *ip4hdr)
{
	return ((ip4hdr->version_ihl & 0xf) << 2);
}

static inline uint8_t *
ipv4_skip_exthdr(struct ipv4_hdr *ip4hdr)
{
	return ((uint8_t *)ip4hdr + ipv4_hdr_len(ip4hdr));
}

static void
process_single_packet(struct rte_mbuf *pkt, const struct ggu_config *ggu_conf)
{
	uint8_t j;
	uint8_t *policy_ptr;
	uint16_t ether_type;
	struct ether_hdr *eth_hdr;
	struct ipv4_hdr *ip4hdr;
	struct ipv6_hdr *ip6hdr;
	struct udp_hdr *udphdr;
	struct ggu_common_hdr *gguhdr;
	uint16_t real_payload_len;
	uint16_t expected_payload_len;
	struct ggu_policy policy;
	uint16_t minimum_size = sizeof(struct ether_hdr);

	eth_hdr = rte_pktmbuf_mtod(pkt, struct ether_hdr *);
	ether_type = rte_be_to_cpu_16(eth_hdr->ether_type);

	switch (ether_type) {
	case ETHER_TYPE_IPv4:
		minimum_size += sizeof(struct ipv4_hdr) +
			sizeof(struct udp_hdr) + sizeof(struct ggu_common_hdr);
		if (pkt->data_len < minimum_size) {
			RTE_LOG(NOTICE, GATEKEEPER,
				"ggu: the IPv4 packet's actual size is %hu, which doesn't have the minimum expected size %hu\n",
				pkt->data_len, minimum_size);
			goto free_packet;
		}

		ip4hdr = rte_pktmbuf_mtod_offset(pkt, 
			struct ipv4_hdr *, sizeof(struct ether_hdr));
		if (ip4hdr->next_proto_id != IPPROTO_UDP) {
			RTE_LOG(ERR, GATEKEEPER,
				"ggu: received non-UDP packets, IPv4 ntuple filter bug!\n");
			goto free_packet;
		}

		if (ip4hdr->dst_addr != ggu_conf->net->back.ip4_addr.s_addr) {
			RTE_LOG(ERR, GATEKEEPER,
				"ggu: received packets not destined to the Gatekeeper server, IPv4 ntuple filter bug!\n");
			goto free_packet;
		}

		minimum_size += ipv4_hdr_len(ip4hdr) - sizeof(*ip4hdr);
		if (pkt->data_len < minimum_size) {
			RTE_LOG(NOTICE, GATEKEEPER,
				"ggu: the IPv4 packet's actual size is %hu, which doesn't have the minimum expected size %hu\n",
				pkt->data_len, minimum_size);
			goto free_packet;
		}

		/*
		 * The ntuple filter supports IPv4 variable headers.
		 * The following code parses IPv4 variable headers.
		 */
		udphdr = (struct udp_hdr *)ipv4_skip_exthdr(ip4hdr);
		break;

	case ETHER_TYPE_IPv6: {
		/*
		 * The UDP header offset in terms of the
		 * beginning of the IPv6 header.
		 */
		int udp_offset;
		uint8_t nexthdr;

		minimum_size += sizeof(struct ipv6_hdr) +
			sizeof(struct udp_hdr) + sizeof(struct ggu_common_hdr);
		if (pkt->data_len < minimum_size) {
			RTE_LOG(NOTICE, GATEKEEPER,
				"ggu: the IPv6 packet's actual size is %hu, which doesn't have the minimum expected size %hu\n",
				pkt->data_len, minimum_size);
			goto free_packet;
		}

		/*
		 * The ntuple filter supports IPv6 variable headers.
		 * The following code parses IPv6 variable headers.
		 */
		ip6hdr = rte_pktmbuf_mtod_offset(pkt, 
			struct ipv6_hdr *, sizeof(struct ether_hdr));

		/*
		 * TODO Given that IPv6 ntuple filter doesn't check
		 * the destination address, it must be done here.
		 * If the IPv6 packet is not destined to
		 * the Gatekeeper server, redirect the packet properly.
		 */
		if (memcmp(ip6hdr->dst_addr,
				ggu_conf->net->back.ip6_addr.s6_addr,
				sizeof(ip6hdr->dst_addr)) != 0) {
			RTE_LOG(NOTICE, GATEKEEPER,
				"ggu: received an IPv6 packet destinated to other host!\n");
			return;
		}

		udp_offset = ipv6_skip_exthdr(ip6hdr, pkt->data_len -
			sizeof(struct ether_hdr), &nexthdr);
		if (udp_offset < 0) {
			RTE_LOG(ERR, GATEKEEPER,
				"ggu: failed to parse the IPv6 packet's extension headers!\n");
			goto free_packet;
		}

		if (nexthdr != IPPROTO_UDP) {
			RTE_LOG(ERR, GATEKEEPER,
				"ggu: received non-UDP packets, IPv6 ntuple filter bug!\n");
			goto free_packet;
		}

		minimum_size += udp_offset - sizeof(*ip6hdr);
		if (pkt->data_len < minimum_size) {
			RTE_LOG(NOTICE, GATEKEEPER,
				"ggu: the IPv6 packet's actual size is %hu, which doesn't have the minimum expected size %hu\n",
				pkt->data_len, minimum_size);
			goto free_packet;
		}

		udphdr = (struct udp_hdr *)((uint8_t *)ip6hdr + udp_offset);
		break;
	}

	default:
		RTE_LOG(NOTICE, GATEKEEPER,
			"ggu: unknown network layer protocol %hu\n",
			ether_type);
		goto free_packet;
		break;
	}

	if (udphdr->src_port != ggu_conf->ggu_src_port ||
			udphdr->dst_port != ggu_conf->ggu_dst_port) {
		RTE_LOG(ERR, GATEKEEPER,
			"ggu: unknown udp src port %hu, dst port %hu, ntuple filter bug!\n",
			rte_be_to_cpu_16(udphdr->src_port),
			rte_be_to_cpu_16(udphdr->dst_port));
		goto free_packet;
	}

	/* XXX Check the UDP checksum. */

	gguhdr = (struct ggu_common_hdr *)&udphdr[1];
	if (gguhdr->v1 != GGU_PD_VER1) {
		RTE_LOG(NOTICE, GATEKEEPER,
			"ggu: unknown policy decision format %hhu\n",
			gguhdr->v1);
		goto free_packet;
	}

	policy_ptr = (uint8_t *)&gguhdr[1];

	real_payload_len = rte_be_to_cpu_16(udphdr->dgram_len);
	expected_payload_len = sizeof(*udphdr) + sizeof(*gguhdr) +
		(gguhdr->n1 + gguhdr->n3) * sizeof(policy.flow.f.v4) +
		(gguhdr->n2 + gguhdr->n4) * sizeof(policy.flow.f.v6) +
		(gguhdr->n1 + gguhdr->n2) * sizeof(policy.params.u.declined) + 
		(gguhdr->n3 + gguhdr->n4) * sizeof(policy.params.u.granted);
	if (real_payload_len < expected_payload_len) {
		RTE_LOG(NOTICE, GATEKEEPER,
			"ggu: the size (%hu) of the payload available in the UDP header doesn't match the expected size (%hu)!\n",
			real_payload_len, expected_payload_len);
		goto free_packet;
	}

	/* Loop over each policy decision on the packet. */

	/* Process the IPv4 decline decisions. */
	memset(&policy, 0, sizeof(policy));
	policy.state = GK_DECLINED;
	policy.flow.proto = ETHER_TYPE_IPv4;
	for (j = 0; j < gguhdr->n1; j++) {
		rte_memcpy(&policy.flow.f.v4, policy_ptr,
			sizeof(policy.flow.f.v4));
		policy_ptr += sizeof(policy.flow.f.v4);
		rte_memcpy(&policy.params.u.declined, policy_ptr,
			sizeof(policy.params.u.declined));
		policy_ptr += sizeof(policy.params.u.declined);
		process_single_policy(&policy, ggu_conf);
	}

	/* Process the IPv6 decline decisions. */
	policy.flow.proto = ETHER_TYPE_IPv6;
	for (j = 0; j < gguhdr->n2; j++) {
		rte_memcpy(&policy.flow.f.v6, policy_ptr,
			sizeof(policy.flow.f.v6));
		policy_ptr += sizeof(policy.flow.f.v6);
		rte_memcpy(&policy.params.u.declined, policy_ptr,
			sizeof(policy.params.u.declined));
		policy_ptr += sizeof(policy.params.u.declined);
		process_single_policy(&policy, ggu_conf);
	}

	/* Process the IPv4 granted decisions. */
	policy.state = GK_GRANTED;
	policy.flow.proto = ETHER_TYPE_IPv4;
	for (j = 0; j < gguhdr->n3; j++) {
		rte_memcpy(&policy.flow.f.v4, policy_ptr,
			sizeof(policy.flow.f.v4));
		policy_ptr += sizeof(policy.flow.f.v4);
		rte_memcpy(&policy.params.u.granted, policy_ptr,
			sizeof(policy.params.u.granted));
		policy_ptr += sizeof(policy.params.u.granted);
		process_single_policy(&policy, ggu_conf);
	}

	/* Process the IPv6 granted decisions. */
	policy.flow.proto = ETHER_TYPE_IPv6;
	for (j = 0; j < gguhdr->n4; j++) {
		rte_memcpy(&policy.flow.f.v6, policy_ptr,
			sizeof(policy.flow.f.v6));
		policy_ptr += sizeof(policy.flow.f.v6);
		rte_memcpy(&policy.params.u.granted, policy_ptr,
			sizeof(policy.params.u.granted));
		policy_ptr += sizeof(policy.params.u.granted);
		process_single_policy(&policy, ggu_conf);
	}

free_packet:
	rte_pktmbuf_free(pkt);
}

static int
ggu_proc(void *arg)
{
	uint32_t lcore = rte_lcore_id();
	struct ggu_config *ggu_conf = (struct ggu_config *)arg;
	uint8_t port_in = ggu_conf->net->back.id;
	uint16_t rx_queue = ggu_conf->rx_queue_back;

	RTE_LOG(NOTICE, GATEKEEPER,
		"ggu: the GK-GT unit is running at lcore = %u\n", lcore);

	while (likely(!exiting)) {
		uint16_t i;
		uint16_t num_rx;
		struct rte_mbuf *bufs[GATEKEEPER_MAX_PKT_BURST];

		/* Load a set of GK-GT packets from the back NIC. */
		num_rx = rte_eth_rx_burst(port_in, rx_queue, bufs,
			GATEKEEPER_MAX_PKT_BURST);
		if (unlikely(num_rx == 0))
			continue;

		for (i = 0; i < num_rx; i++)
			process_single_packet(bufs[i], ggu_conf);
	}

	RTE_LOG(NOTICE, GATEKEEPER,
		"ggu: the GK-GT unit at lcore = %u is exiting\n", lcore);
	return cleanup_ggu(ggu_conf);
}

static int
ggu_state1(void *arg)
{
	struct ggu_config *ggu_conf = arg;
	int ret = get_queue_id(&ggu_conf->net->back, QUEUE_TYPE_RX,
		ggu_conf->lcore_id);
	if (ret < 0) {
		RTE_LOG(ERR, GATEKEEPER, "ggu: cannot assign an RX queue for the back interface for lcore %u\n",
			ggu_conf->lcore_id);
		return ret;
	}
	ggu_conf->rx_queue_back = ret;
	return 0;
}

static int
ggu_state2(void *arg)
{
	struct ggu_config *ggu_conf = arg;

	/*
	 * Setup the ntuple filters that assign the GK-GT packets
	 * to its queue for both IPv4 and IPv6 addresses.
	 */
	return ntuple_filter_add(ggu_conf->net->back.id,
		ggu_conf->net->back.ip4_addr.s_addr,
		ggu_conf->ggu_src_port, UINT16_MAX,
		ggu_conf->ggu_dst_port, UINT16_MAX,
		IPPROTO_UDP, ggu_conf->rx_queue_back, false);
}

int
run_ggu(struct net_config *net_conf,
	struct gk_config *gk_conf, struct ggu_config *ggu_conf)
{
	int ret;

	if (ggu_conf == NULL || net_conf == NULL || gk_conf == NULL) {
		ret = -1;
		goto out;
	}

	if (!net_conf->back_iface_enabled) {
		RTE_LOG(ERR, GATEKEEPER, "ggu: back interface is required\n");
		ret = -1;
		goto out;
	}

	ret = net_launch_at_stage1(net_conf, 0, 0, 1, 0, ggu_state1, ggu_conf);
	if (ret < 0)
		goto out;

	ret = launch_at_stage2(ggu_state2, ggu_conf);
	if (ret < 0)
		goto stage1;

	ret = launch_at_stage3("ggu", ggu_proc, ggu_conf, ggu_conf->lcore_id);
	if (ret < 0)
		goto stage2;

	ggu_conf->net = net_conf;
	gk_conf_hold(gk_conf);
	ggu_conf->gk = gk_conf;

	/*
	 * Convert port numbers in CPU order to network order
	 * to avoid recomputation for each packet.
	 */
	ggu_conf->ggu_src_port = rte_cpu_to_be_16(ggu_conf->ggu_src_port);
	ggu_conf->ggu_dst_port = rte_cpu_to_be_16(ggu_conf->ggu_dst_port);

	ret = 0;
	goto out;

stage2:
	pop_n_at_stage2(1);
stage1:
	pop_n_at_stage1(1);
out:
	return ret;
}

/*
 * There should be only one ggu_config instance.
 * Return an error if trying to allocate the second instance.
 */
struct ggu_config *
alloc_ggu_conf(void)
{
	static rte_atomic16_t num_ggu_conf_alloc = RTE_ATOMIC16_INIT(0);

	if (rte_atomic16_test_and_set(&num_ggu_conf_alloc) == 1)
		return rte_calloc("ggu_config", 1, sizeof(struct ggu_config), 0);
	else {
		RTE_LOG(ERR, GATEKEEPER,
			"ggu: trying to allocate the second instance of struct ggu_config\n");
		return NULL;
	}
}

int
cleanup_ggu(struct ggu_config *ggu_conf)
{
	ggu_conf->net = NULL;
	gk_conf_put(ggu_conf->gk);
	ggu_conf->gk = NULL;
	rte_free(ggu_conf);

	return 0;
}
