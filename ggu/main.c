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

#include "gatekeeper_acl.h"
#include "gatekeeper_ggu.h"
#include "gatekeeper_gk.h"
#include "gatekeeper_main.h"
#include "gatekeeper_config.h"
#include "gatekeeper_launch.h"
#include "gatekeeper_l2.h"
#include "gatekeeper_varip.h"

static struct ggu_config *ggu_conf;

static inline const char *
filter_name(const struct gatekeeper_if *iface)
{
	return iface->hw_filter_ntuple ? "ntuple filter" : "ACL";
}

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

static void
process_single_packet(struct rte_mbuf *pkt, const struct ggu_config *ggu_conf)
{
	uint8_t j;
	uint8_t *policy_ptr;
	uint16_t ether_type;
	struct ether_hdr *eth_hdr;
	void *l3_hdr;
	struct ipv4_hdr *ip4hdr;
	struct ipv6_hdr *ip6hdr;
	struct udp_hdr *udphdr;
	struct ggu_common_hdr *gguhdr;
	uint16_t real_payload_len;
	uint16_t expected_payload_len;
	struct ggu_policy policy;
	struct gatekeeper_if *back = &ggu_conf->net->back;
	uint16_t minimum_size;
	size_t l2_len;

	eth_hdr = rte_pktmbuf_mtod(pkt, struct ether_hdr *);
	ether_type = rte_be_to_cpu_16(pkt_in_skip_l2(pkt, eth_hdr, &l3_hdr));
	l2_len = pkt_in_l2_hdr_len(pkt);
	minimum_size = l2_len;

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

		ip4hdr = l3_hdr;
		if (ip4hdr->next_proto_id != IPPROTO_UDP) {
			RTE_LOG(ERR, GATEKEEPER,
				"ggu: received non-UDP packets, IPv4 %s bug!\n",
				filter_name(back));
			goto free_packet;
		}

		if (ip4hdr->dst_addr != back->ip4_addr.s_addr) {
			RTE_LOG(ERR, GATEKEEPER,
				"ggu: received packets not destined to the Gatekeeper server, IPv4 %s bug!\n",
				filter_name(back));
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
		 * The ntuple filter/ACL supports IPv4 variable headers.
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
		 * The ntuple filter/ACL supports IPv6 variable headers.
		 * The following code parses IPv6 variable headers.
		 */
		ip6hdr = l3_hdr;

		/*
		 * TODO Given that IPv6 ntuple filter doesn't check
		 * the destination address, it must be done here.
		 * If the IPv6 packet is not destined to
		 * the Gatekeeper server, redirect the packet properly.
		 */
		if (back->hw_filter_ntuple && memcmp(ip6hdr->dst_addr,
				back->ip6_addr.s6_addr,
				sizeof(ip6hdr->dst_addr)) != 0) {
			RTE_LOG(NOTICE, GATEKEEPER,
				"ggu: received an IPv6 packet destinated to other host!\n");
			return;
		}

		udp_offset = ipv6_skip_exthdr(ip6hdr, pkt->data_len - l2_len,
			&nexthdr);
		if (udp_offset < 0) {
			RTE_LOG(ERR, GATEKEEPER,
				"ggu: failed to parse the IPv6 packet's extension headers!\n");
			goto free_packet;
		}

		if (nexthdr != IPPROTO_UDP) {
			RTE_LOG(ERR, GATEKEEPER,
				"ggu: received non-UDP packets, IPv6 %s bug!\n",
				filter_name(back));
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
			"ggu: unknown udp src port %hu, dst port %hu, %s bug!\n",
			rte_be_to_cpu_16(udphdr->src_port),
			rte_be_to_cpu_16(udphdr->dst_port),
			filter_name(back));
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

/* Information needed to submit GGU packets to the GGU block. */
struct ggu_request {
	/* GT-GK Unit packets. */
	struct rte_mbuf **pkts;

	/* Number of packets stored in @pkts. */
	unsigned int    num_pkts;
};

static int
submit_ggu(struct rte_mbuf **pkts, unsigned int num_pkts,
	__attribute__((unused)) struct gatekeeper_if *iface)
{
	struct ggu_request *req = mb_alloc_entry(&ggu_conf->mailbox);
	unsigned int i;
	int ret;

	RTE_VERIFY(num_pkts <= RTE_DIM(pkts));

	if (req == NULL) {
		RTE_LOG(ERR, GATEKEEPER,
			"ggu: %s: allocation of mailbox message failed\n",
			__func__);
		ret = -ENOMEM;
		goto free_pkts;
	}

	req->num_pkts = num_pkts;
	req->pkts = pkts;

	ret = mb_send_entry(&ggu_conf->mailbox, req);
	if (ret < 0) {
		RTE_LOG(ERR, GATEKEEPER,
			"ggu: %s: failed to enqueue message to mailbox\n",
			__func__);
		goto free_pkts;
	}

	return 0;

free_pkts:
	for (i = 0; i < num_pkts; i++)
		rte_pktmbuf_free(pkts[i]);
	return ret;
}

static int
ggu_proc(void *arg)
{
	uint32_t lcore = rte_lcore_id();
	struct ggu_config *ggu_conf = (struct ggu_config *)arg;
	uint16_t port_in = ggu_conf->net->back.id;
	uint16_t rx_queue = ggu_conf->rx_queue_back;
	unsigned int i;
	uint16_t gatekeeper_max_pkt_burst =
		get_gatekeeper_conf()->gatekeeper_max_pkt_burst;

	RTE_LOG(NOTICE, GATEKEEPER,
		"ggu: the GK-GT unit is running at lcore = %u\n", lcore);

	/*
	 * Load a set of GK-GT packets from the back NIC
	 * or from the GGU mailbox.
	 */
	if (ggu_conf->net->back.hw_filter_ntuple) {
		while (likely(!exiting)) {
			struct rte_mbuf *bufs[gatekeeper_max_pkt_burst];
			uint16_t num_rx = rte_eth_rx_burst(port_in, rx_queue,
				bufs, gatekeeper_max_pkt_burst);

			if (unlikely(num_rx == 0))
				continue;

			for (i = 0; i < num_rx; i++)
				process_single_packet(bufs[i], ggu_conf);
		}
	} else {
		while (likely(!exiting)) {
			unsigned int mailbox_burst_size =
				ggu_conf->mailbox_burst_size;
			struct ggu_request *reqs[mailbox_burst_size];
			unsigned int num_reqs =
				mb_dequeue_burst(&ggu_conf->mailbox,
				(void **)reqs, mailbox_burst_size);

			if (unlikely(num_reqs == 0))
				continue;

			for (i = 0; i < num_reqs; i++) {
				unsigned int j;
				for (j = 0; j < reqs[i]->num_pkts; j++) {
					process_single_packet(reqs[i]->pkts[j],
						ggu_conf);
				}
			}
		}
	}

	RTE_LOG(NOTICE, GATEKEEPER,
		"ggu: the GK-GT unit at lcore = %u is exiting\n", lcore);
	return cleanup_ggu(ggu_conf);
}

static int
ggu_stage1(void *arg)
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

static void
fill_ggu4_rule(struct ipv4_acl_rule *rule, struct ggu_config *ggu_conf)
{
	rule->data.category_mask = 0x1;
	rule->data.priority = 1;
	/* Userdata is filled in in register_ipv4_acl(). */

	rule->field[PROTO_FIELD_IPV4].value.u8 = IPPROTO_UDP;
	rule->field[PROTO_FIELD_IPV4].mask_range.u8 = 0xFF;

	rule->field[DST_FIELD_IPV4].value.u32 =
		rte_be_to_cpu_32(ggu_conf->net->back.ip4_addr.s_addr);
	rule->field[DST_FIELD_IPV4].mask_range.u32 = 32;

	rule->field[SRCP_FIELD_IPV4].value.u16 = ggu_conf->ggu_src_port;
	rule->field[SRCP_FIELD_IPV4].mask_range.u16 = 0xFFFF;
	rule->field[DSTP_FIELD_IPV4].value.u16 = ggu_conf->ggu_dst_port;
	rule->field[DSTP_FIELD_IPV4].mask_range.u16 = 0xFFFF;
}

static void
fill_ggu6_rule(struct ipv6_acl_rule *rule, struct ggu_config *ggu_conf)
{
	uint32_t *ptr32 = (uint32_t *)&ggu_conf->net->back.ip6_addr.s6_addr;
	int i;

	rule->data.category_mask = 0x1;
	rule->data.priority = 1;
	/* Userdata is filled in in register_ipv6_acl(). */

	rule->field[PROTO_FIELD_IPV6].value.u8 = IPPROTO_UDP;
	rule->field[PROTO_FIELD_IPV6].mask_range.u8 = 0xFF;

	for (i = DST1_FIELD_IPV6; i <= DST4_FIELD_IPV6; i++) {
		rule->field[i].value.u32 = rte_be_to_cpu_32(*ptr32);
		rule->field[i].mask_range.u32 = 32;
		ptr32++;
	}

	rule->field[SRCP_FIELD_IPV6].value.u16 = ggu_conf->ggu_src_port;
	rule->field[SRCP_FIELD_IPV6].mask_range.u16 = 0xFFFF;
	rule->field[DSTP_FIELD_IPV6].value.u16 = ggu_conf->ggu_dst_port;
	rule->field[DSTP_FIELD_IPV6].mask_range.u16 = 0xFFFF;
}

static int
ggu_stage2(void *arg)
{
	struct ggu_config *ggu_conf = arg;
	bool ipv4_configured = ipv4_if_configured(&ggu_conf->net->back);
	bool ipv6_configured = ipv6_if_configured(&ggu_conf->net->back);
	struct ipv4_acl_rule ipv4_rule = { };
	struct ipv6_acl_rule ipv6_rule = { };
	int ret;

	/*
	 * Setup the ntuple filters that assign the GK-GT packets
	 * to its queue for both IPv4 and IPv6 addresses.
	 */
	if (ggu_conf->net->back.hw_filter_ntuple) {
		return ntuple_filter_add(ggu_conf->net->back.id,
			ggu_conf->net->back.ip4_addr.s_addr,
			ggu_conf->ggu_src_port, UINT16_MAX,
			ggu_conf->ggu_dst_port, UINT16_MAX,
			IPPROTO_UDP, ggu_conf->rx_queue_back,
			ipv4_configured, ipv6_configured);
	}

	/*
	 * ntuple filter is not supported, so add ACL rules
	 * to capture GGU packets. Since the channel that
	 * GGU packets are sent through is controlled by
	 * Gatekeeper, GGU packets won't have variable
	 * headers, so we don't need a match function.
	 */

	if (ipv4_configured) {
		fill_ggu4_rule(&ipv4_rule, ggu_conf);
		ret = register_ipv4_acl(&ipv4_rule, 1,
			submit_ggu, NULL, &ggu_conf->net->back);
		if (ret < 0) {
			RTE_LOG(ERR, GATEKEEPER, "ggu: could not register IPv4 GGU ACL on back iface\n");
			return ret;
		}
	}

	if (ipv6_configured) {
		fill_ggu6_rule(&ipv6_rule, ggu_conf);
		ret = register_ipv6_acl(&ipv6_rule, 1,
			submit_ggu, NULL, &ggu_conf->net->back);
		if (ret < 0) {
			RTE_LOG(ERR, GATEKEEPER, "ggu: could not register IPv6 GGU ACL on back iface\n");
			return ret;
		}
	}

	return 0;
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

	ret = net_launch_at_stage1(net_conf, 0, 0, 1, 0, ggu_stage1, ggu_conf);
	if (ret < 0)
		goto out;

	ret = launch_at_stage2(ggu_stage2, ggu_conf);
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

	ret = init_mailbox("ggu_mb", ggu_conf->mailbox_max_entries,
		sizeof(struct ggu_request), ggu_conf->mailbox_mem_cache_size,
		ggu_conf->lcore_id, &ggu_conf->mailbox);
	if (ret < 0)
		goto stage3;

	goto out;
stage3:
	pop_n_at_stage3(1);
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

	if (rte_atomic16_test_and_set(&num_ggu_conf_alloc) == 1) {
		ggu_conf = rte_calloc("ggu_config", 1,
			sizeof(struct ggu_config), 0);
		return ggu_conf;
	} else {
		RTE_LOG(ERR, GATEKEEPER,
			"ggu: trying to allocate the second instance of struct ggu_config\n");
		return NULL;
	}
}

int
cleanup_ggu(struct ggu_config *ggu_conf)
{
	destroy_mailbox(&ggu_conf->mailbox);
	ggu_conf->net = NULL;
	gk_conf_put(ggu_conf->gk);
	ggu_conf->gk = NULL;
	rte_free(ggu_conf);

	return 0;
}
