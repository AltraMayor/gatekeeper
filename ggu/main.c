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
#include "gatekeeper_main.h"
#include "gatekeeper_config.h"
#include "gatekeeper_launch.h"
#include "gatekeeper_l2.h"
#include "gatekeeper_varip.h"
#include "gatekeeper_log_ratelimit.h"

static struct ggu_config *ggu_conf;

static void
process_single_policy(struct ggu_policy *policy, void *arg)
{
	const struct ggu_config *ggu_conf = arg;
	uint32_t flow_hash_val = rss_flow_hash(&ggu_conf->net->front,
		&policy->flow);
	struct gk_cmd_entry *entry;
	/*
	 * Obtain mailbox of that GK block,
	 * and send the policy decision to the GK block.
	 */
	struct mailbox *mb =
		get_responsible_gk_mailbox(flow_hash_val, ggu_conf->gk);

	if (mb == NULL)
		return;

	entry = mb_alloc_entry(mb);
	if (entry == NULL)
		return;

	entry->op = GK_ADD_POLICY_DECISION;
	entry->u.ggu.flow_hash_val = flow_hash_val;
	entry->u.ggu.policy.state = policy->state;
	rte_memcpy(&entry->u.ggu.policy.flow, &policy->flow,
		sizeof(entry->u.ggu.policy.flow));

	switch (policy->state) {
	case GK_GRANTED:
		entry->u.ggu.policy.params.granted = policy->params.granted;
		break;

	case GK_DECLINED:
		entry->u.ggu.policy.params.declined = policy->params.declined;
		break;

	case GK_BPF:
		if (gk_init_bpf_cookie(ggu_conf->gk,
				policy->params.bpf.program_index,
				&policy->params.bpf.cookie) < 0)
			goto error;
		/*
		 * After calling gk_init_bpf_cookie(),
		 * the whole cookie may be used.
		 */
		policy->params.bpf.cookie_len =
			sizeof(policy->params.bpf.cookie);
		entry->u.ggu.policy.params.bpf = policy->params.bpf;
		break;

	default:
		G_LOG(ERR, "%s(): unknown policy state %hhu\n",
			__func__, policy->state);
		goto error;
	}

	mb_send_entry(mb, entry);
	return;

error:
	mb_free_entry(mb, entry);
}

void
ggu_policy_iterator(struct ggu_decision *ggu_decision,
	unsigned int decision_list_len, ggu_policy_fn policy_fn,
	void *policy_arg)
{
	while (decision_list_len >= sizeof(*ggu_decision)) {
		struct ggu_policy policy;
		uint8_t decision_type = ggu_decision->type;
		size_t decision_len = sizeof(*ggu_decision);
		size_t params_offset;

		if (ggu_decision->res1 != 0 || ggu_decision->res2 != 0) {
			G_LOG(NOTICE, "%s(): reserved fields of GGU decisions should be 0 but are %hhu and %hu\n",
				__func__, ggu_decision->res1,
				rte_be_to_cpu_16(ggu_decision->res2));
			return;
		}

		/* Verify decision length and read in flow information. */
		switch (decision_type) {
		case GGU_DEC_IPV4_DECLINED:
			decision_len += sizeof(policy.flow.f.v4) +
				sizeof(policy.params.declined);
			if (decision_list_len < decision_len) {
				G_LOG(WARNING, "%s(): malformed IPv4 declined decision\n",
					__func__);
				return;
			}
			policy.state = GK_DECLINED;
			policy.flow.proto = RTE_ETHER_TYPE_IPV4;
			rte_memcpy(&policy.flow.f.v4, ggu_decision->ip_flow,
				sizeof(policy.flow.f.v4));
			params_offset = sizeof(policy.flow.f.v4);
			break;
		case GGU_DEC_IPV6_DECLINED:
			decision_len += sizeof(policy.flow.f.v6) +
				sizeof(policy.params.declined);
			if (decision_list_len < decision_len) {
				G_LOG(WARNING, "%s(): malformed IPv6 declined decision\n",
					__func__);
				return;
			}
			policy.state = GK_DECLINED;
			policy.flow.proto = RTE_ETHER_TYPE_IPV6;
			rte_memcpy(&policy.flow.f.v6, ggu_decision->ip_flow,
				sizeof(policy.flow.f.v6));
			params_offset = sizeof(policy.flow.f.v6);
			break;
		case GGU_DEC_IPV4_GRANTED:
			decision_len += sizeof(policy.flow.f.v4) +
				sizeof(policy.params.granted);
			if (decision_list_len < decision_len) {
				G_LOG(WARNING, "%s(): malformed IPv4 granted decision\n",
					__func__);
				return;
			}
			policy.state = GK_GRANTED;
			policy.flow.proto = RTE_ETHER_TYPE_IPV4;
			rte_memcpy(&policy.flow.f.v4, ggu_decision->ip_flow,
				sizeof(policy.flow.f.v4));
			params_offset = sizeof(policy.flow.f.v4);
			break;
		case GGU_DEC_IPV6_GRANTED:
			decision_len += sizeof(policy.flow.f.v6) +
				sizeof(policy.params.granted);
			if (decision_list_len < decision_len) {
				G_LOG(WARNING, "%s(): malformed IPv6 granted decision\n",
					__func__);
				return;
			}
			policy.state = GK_GRANTED;
			policy.flow.proto = RTE_ETHER_TYPE_IPV6;
			rte_memcpy(&policy.flow.f.v6, ggu_decision->ip_flow,
				sizeof(policy.flow.f.v6));
			params_offset = sizeof(policy.flow.f.v6);
			break;
		case GGU_DEC_IPV4_BPF:
			decision_len += sizeof(policy.flow.f.v4) +
				sizeof(struct ggu_bpf_wire);
			if (decision_list_len < decision_len) {
				G_LOG(WARNING, "%s(): malformed IPv4 BPF decision\n",
					__func__);
				return;
			}
			policy.state = GK_BPF;
			policy.flow.proto = RTE_ETHER_TYPE_IPV4;
			rte_memcpy(&policy.flow.f.v4, ggu_decision->ip_flow,
				sizeof(policy.flow.f.v4));
			params_offset = sizeof(policy.flow.f.v4);
			break;
		case GGU_DEC_IPV6_BPF:
			decision_len += sizeof(policy.flow.f.v6) +
				sizeof(struct ggu_bpf_wire);
			if (decision_list_len < decision_len) {
				G_LOG(WARNING, "%s(): malformed IPv6 BPF decision\n",
					__func__);
				return;
			}
			policy.state = GK_BPF;
			policy.flow.proto = RTE_ETHER_TYPE_IPV6;
			rte_memcpy(&policy.flow.f.v6, ggu_decision->ip_flow,
				sizeof(policy.flow.f.v6));
			params_offset = sizeof(policy.flow.f.v6);
			break;
		default:
			G_LOG(WARNING, "%s(): unexpected decision type: %hu\n",
				__func__, decision_type);
			return;
		}

		/* Read in decision parameters. */
		switch (decision_type) {
		case GGU_DEC_IPV4_GRANTED:
			/* FALLTHROUGH */
		case GGU_DEC_IPV6_GRANTED: {
			struct ggu_granted *granted_be = (struct ggu_granted *)
				(ggu_decision->ip_flow + params_offset);
			policy.params.granted.tx_rate_kib_sec =
				rte_be_to_cpu_32(granted_be->tx_rate_kib_sec);
			policy.params.granted.cap_expire_sec =
				rte_be_to_cpu_32(granted_be->cap_expire_sec);
			policy.params.granted.next_renewal_ms =
				rte_be_to_cpu_32(granted_be->next_renewal_ms);
			policy.params.granted.renewal_step_ms =
				rte_be_to_cpu_32(granted_be->renewal_step_ms);
			break;
		}

		case GGU_DEC_IPV4_DECLINED:
			/* FALLTHROUGH */
		case GGU_DEC_IPV6_DECLINED: {
			struct ggu_declined *declined_be =
				(struct ggu_declined *)
				(ggu_decision->ip_flow + params_offset);
			policy.params.declined.expire_sec =
				rte_be_to_cpu_32(declined_be->expire_sec);
			break;
		}

		case GGU_DEC_IPV4_BPF:
			/* FALLTHROUGH */
		case GGU_DEC_IPV6_BPF: {
			struct ggu_bpf_wire *bpf_wire_be =
				(struct ggu_bpf_wire *)
				(ggu_decision->ip_flow + params_offset);
			unsigned int cookie_len;
			if (bpf_wire_be->reserved != 0) {
				G_LOG(WARNING, "%s(): malformed BPF decision, reserved=%u\n",
					__func__, bpf_wire_be->reserved);
				return;
			}
			cookie_len = 4 * bpf_wire_be->cookie_len_4by;
			if (cookie_len > sizeof(struct gk_bpf_cookie)) {
				G_LOG(WARNING, "%s(): malformed BPF decision, cookie_len=%u\n",
					__func__, cookie_len);
				return;
			}
			decision_len += cookie_len;
			if (decision_list_len < decision_len) {
				G_LOG(WARNING, "%s(): malformed BPF decision (too short)\n",
					__func__);
				return;
			}
			policy.params.bpf.expire_sec =
				rte_be_to_cpu_32(bpf_wire_be->expire_sec);
			policy.params.bpf.program_index =
				bpf_wire_be->program_index;
			policy.params.bpf.reserved = 0;
			policy.params.bpf.cookie_len = cookie_len;
			/*
			 * Byte order is responsibility of the init function
			 * of the GK BPF program.
			 */
			rte_memcpy(&policy.params.bpf.cookie,
				bpf_wire_be->cookie, cookie_len);
			memset(((uint8_t *)&policy.params.bpf.cookie) +
				cookie_len, 0,
				sizeof(policy.params.bpf.cookie) - cookie_len);
			break;
		}

		default:
			rte_panic("%s(): found an unknown decision type after previously verifying it: %hhu\n",
				__func__, decision_type);
		}

		policy_fn(&policy, policy_arg);
		ggu_decision = (struct ggu_decision *)
			(((uint8_t *)ggu_decision) + decision_len);
		decision_list_len -= decision_len;
	}

	if (decision_list_len != 0) {
		G_LOG(WARNING, "%s(): notification packet had partial decision list\n",
			__func__);
	}
}

static void
process_single_packet(struct rte_mbuf *pkt, struct ggu_config *ggu_conf)
{
	uint16_t ether_type;
	struct rte_ether_hdr *eth_hdr;
	void *l3_hdr;
	struct rte_udp_hdr *udphdr;
	uint16_t pkt_udp_checksum, cal_udp_checksum;
	struct ggu_common_hdr *gguhdr;
	struct ggu_decision *ggu_decision;
	uint16_t real_payload_len;
	uint16_t expected_payload_len;
	uint16_t decision_list_len;
	struct gatekeeper_if *back = &ggu_conf->net->back;
	uint16_t minimum_size;
	size_t l2_len;
	int l3_len;

	eth_hdr = rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);
	ether_type = rte_be_to_cpu_16(pkt_in_skip_l2(pkt, eth_hdr, &l3_hdr));
	l2_len = pkt_in_l2_hdr_len(pkt);
	minimum_size = l2_len;

	switch (ether_type) {
	case RTE_ETHER_TYPE_IPV4: {
		struct rte_ipv4_hdr *ip4hdr;

		minimum_size += sizeof(struct rte_ipv4_hdr) +
			sizeof(struct rte_udp_hdr) +
			sizeof(struct ggu_common_hdr);
		if (pkt->data_len < minimum_size) {
			G_LOG(NOTICE, "%s(): the IPv4 packet's actual size is %hu, which doesn't have the minimum expected size %hu\n",
				__func__, pkt->data_len, minimum_size);
			goto free_packet;
		}

		ip4hdr = l3_hdr;
		if (ip4hdr->next_proto_id != IPPROTO_UDP) {
			G_LOG(ERR, "%s(): received non-UDP packets, IPv4 filter bug\n",
				__func__);
			goto free_packet;
		}

		if (ip4hdr->dst_addr != back->ip4_addr.s_addr) {
			G_LOG(ERR, "%s(): received packets not destined to the Gatekeeper server, IPv4 filter bug\n",
				__func__);
			goto free_packet;
		}

		if (rte_ipv4_frag_pkt_is_fragmented(ip4hdr)) {
			G_LOG(WARNING, "%s(): received IPv4 fragmented packets destined to the Gatekeeper server\n",
				__func__);
			goto free_packet;
		}

		l3_len = ipv4_hdr_len(ip4hdr);

		/*
		 * Base IPv4 header length was already accounted for,
		 * so add in any extra bytes from extension header(s).
		 */
		minimum_size += l3_len - sizeof(*ip4hdr);
		if (pkt->data_len < minimum_size) {
			G_LOG(NOTICE, "%s(): the IPv4 packet's actual size is %hu, which doesn't have the minimum expected size %hu\n",
				__func__, pkt->data_len, minimum_size);
			goto free_packet;
		}

		/*
		 * The ntuple filter/ACL supports IPv4 variable headers.
		 * The following code parses IPv4 variable headers.
		 */
		udphdr = (struct rte_udp_hdr *)ipv4_skip_exthdr(ip4hdr);
		break;
	}
	case RTE_ETHER_TYPE_IPV6: {
		struct rte_ipv6_hdr *ip6hdr;
		uint8_t nexthdr;

		minimum_size += sizeof(struct rte_ipv6_hdr) +
			sizeof(struct rte_udp_hdr) +
			sizeof(struct ggu_common_hdr);
		if (pkt->data_len < minimum_size) {
			G_LOG(NOTICE, "%s(): the IPv6 packet's actual size is %hu, which doesn't have the minimum expected size %hu\n",
				__func__, pkt->data_len, minimum_size);
			goto free_packet;
		}

		/*
		 * The ntuple filter/ACL supports IPv6 variable headers.
		 * The following code parses IPv6 variable headers.
		 */
		ip6hdr = l3_hdr;

		if (rte_ipv6_frag_get_ipv6_fragment_header(ip6hdr) != NULL) {
			G_LOG(WARNING, "%s(): received IPv6 fragmented packets destined to the Gatekeeper server\n",
				__func__);
			goto free_packet;
		}

		l3_len = ipv6_skip_exthdr(ip6hdr, pkt->data_len - l2_len,
			&nexthdr);
		if (l3_len < 0) {
			G_LOG(ERR, "%s(): failed to parse the IPv6 packet's extension headers\n",
				__func__);
			goto free_packet;
		}

		if (nexthdr != IPPROTO_UDP) {
			G_LOG(ERR, "%s(): received non-UDP packets, IPv6 filter bug\n",
				__func__);
			goto free_packet;
		}

		/*
		 * Base IPv6 header length was already accounted for,
		 * so add in any extra bytes from extension header(s).
		 */
		minimum_size += l3_len - sizeof(*ip6hdr);
		if (pkt->data_len < minimum_size) {
			G_LOG(NOTICE, "%s(): the IPv6 packet's actual size is %hu, which doesn't have the minimum expected size %hu\n",
				__func__, pkt->data_len, minimum_size);
			goto free_packet;
		}

		udphdr = (struct rte_udp_hdr *)((uint8_t *)ip6hdr + l3_len);
		break;
	}

	default:
		G_LOG(NOTICE, "%s(): unknown network layer protocol %hu\n",
			__func__, ether_type);
		goto free_packet;
		break;
	}

	if (udphdr->src_port != ggu_conf->ggu_src_port ||
			udphdr->dst_port != ggu_conf->ggu_dst_port) {
		G_LOG(ERR, "%s(): unknown UDP src port %hu, dst port %hu, filter bug\n",
			__func__, rte_be_to_cpu_16(udphdr->src_port),
			rte_be_to_cpu_16(udphdr->dst_port));
		goto free_packet;
	}

	real_payload_len = pkt->data_len - l2_len - l3_len;
	expected_payload_len = rte_be_to_cpu_16(udphdr->dgram_len);
	if (real_payload_len != expected_payload_len) {
		G_LOG(NOTICE, "%s(): the size (%hu) of the payload available in the UDP header doesn't match the expected size (%hu)\n",
			__func__, real_payload_len, expected_payload_len);
		goto free_packet;
	}

	pkt_udp_checksum = udphdr->dgram_cksum;
	udphdr->dgram_cksum = 0;

	if (ether_type == RTE_ETHER_TYPE_IPV4) {
		cal_udp_checksum = rte_ipv4_udptcp_cksum(l3_hdr, udphdr);
		if (pkt_udp_checksum != cal_udp_checksum) {
			G_LOG(ERR, "%s(): the IPv4 packet's UDP checksum (%hu) doesn't match the calculated checksum (%hu)\n",
				__func__, pkt_udp_checksum, cal_udp_checksum);
			goto free_packet;
		}
	} else {
		cal_udp_checksum = rte_ipv6_udptcp_cksum(l3_hdr, udphdr);
		if (pkt_udp_checksum != cal_udp_checksum) {
			G_LOG(ERR, "%s(): the IPv6 packet's UDP checksum (%hu) doesn't match the calculated checksum (%hu)\n",
				__func__, pkt_udp_checksum, cal_udp_checksum);
			goto free_packet;
		}
	}

	gguhdr = (struct ggu_common_hdr *)&udphdr[1];
	if (gguhdr->version != GGU_PD_VER) {
		G_LOG(NOTICE, "%s(): unknown policy decision format %hhu\n",
			__func__, gguhdr->version);
		goto free_packet;
	}
	if (gguhdr->res1 != 0 || gguhdr->res2 != 0) {
		G_LOG(NOTICE, "%s(): reserved fields of GGU header should be 0 but are %hhu and %hu\n",
			__func__, gguhdr->res1, rte_be_to_cpu_16(gguhdr->res2));
		goto free_packet;
	}

	/* @minimum_size is length of all headers, including GGU. */
	decision_list_len = pkt->data_len - minimum_size;
	ggu_decision = gguhdr->decisions;

	/* Loop over each policy decision in the packet. */
	ggu_policy_iterator(ggu_decision, decision_list_len,
		process_single_policy, ggu_conf);

free_packet:
	rte_pktmbuf_free(pkt);
}

/* Information needed to submit GGU packets to the GGU block. */
struct ggu_request {
	/* Number of packets stored in @pkts. */
	unsigned int    num_pkts;

	/* GT-GK Unit packets. */
	struct rte_mbuf *pkts[0];
};

static int
submit_ggu(struct rte_mbuf **pkts, unsigned int num_pkts,
	__attribute__((unused)) struct gatekeeper_if *iface)
{
	struct ggu_request *req = mb_alloc_entry(&ggu_conf->mailbox);
	int ret;

	RTE_VERIFY(num_pkts <= ggu_conf->mailbox_max_pkt_burst);

	if (req == NULL) {
		G_LOG(ERR,
			"%s: allocation of mailbox message failed\n",
			__func__);
		ret = -ENOMEM;
		goto free_pkts;
	}

	req->num_pkts = num_pkts;
	rte_memcpy(req->pkts, pkts, sizeof(*req->pkts) * num_pkts);

	ret = mb_send_entry(&ggu_conf->mailbox, req);
	if (ret < 0) {
		G_LOG(ERR,
			"%s: failed to enqueue message to mailbox\n",
			__func__);
		goto free_pkts;
	}

	return 0;

free_pkts:
	rte_pktmbuf_free_bulk(pkts, num_pkts);
	return ret;
}

static void
process_back_nic(struct ggu_config *ggu_conf,
	uint16_t port_in, uint16_t rx_queue, uint16_t max_pkt_burst)
{
	struct rte_mbuf *bufs[max_pkt_burst];
	uint16_t num_rx = rte_eth_rx_burst(port_in, rx_queue,
		bufs, max_pkt_burst);
	unsigned int i;

	if (unlikely(num_rx == 0))
		return;

	for (i = 0; i < num_rx; i++)
		process_single_packet(bufs[i], ggu_conf);
}

static void
process_mb(struct ggu_config *ggu_conf)
{
	unsigned int mailbox_burst_size = ggu_conf->mailbox_burst_size;
	struct ggu_request *reqs[mailbox_burst_size];
	unsigned int num_reqs = mb_dequeue_burst(&ggu_conf->mailbox,
		(void **)reqs, mailbox_burst_size);
	unsigned int i;

	if (unlikely(num_reqs == 0))
		return;

	for (i = 0; i < num_reqs; i++) {
		unsigned int j;
		for (j = 0; j < reqs[i]->num_pkts; j++)
			process_single_packet(reqs[i]->pkts[j], ggu_conf);
	}

	mb_free_entry_bulk(&ggu_conf->mailbox, (void * const *)reqs, num_reqs);
}

static int
ggu_proc(void *arg)
{
	struct ggu_config *ggu_conf = arg;
	uint16_t port_in = ggu_conf->net->back.id;
	uint16_t rx_queue = ggu_conf->rx_queue_back;
	uint16_t max_pkt_burst = ggu_conf->max_pkt_burst;

	G_LOG(NOTICE, "The GT-GK unit is running at tid = %u\n", rte_gettid());

	if (needed_caps(0, NULL) < 0) {
		G_LOG(ERR, "Could not set needed capabilities\n");
		exiting = true;
	}

	/*
	 * Load sets of GT-GK packets from the back NIC
	 * or from the GGU mailbox.
	 */
	while (likely(!exiting)) {
		if (ggu_conf->rx_method_back & RX_METHOD_NIC) {
			process_back_nic(ggu_conf, port_in,
				rx_queue, max_pkt_burst);
		}

		if (ggu_conf->rx_method_back & RX_METHOD_MB)
			process_mb(ggu_conf);
	}

	G_LOG(NOTICE, "The GT-GK unit is exiting\n");
	return cleanup_ggu(ggu_conf);
}

static int
ggu_stage1(void *arg)
{
	struct ggu_config *ggu_conf = arg;
	int ret;

	/*
	 * GGU should only get its own RX queue if RSS is enabled,
	 * even if ntuple filter is not enabled.
	 *
	 * If RSS is disabled, then the network configuration can
	 * tell that it should ignore all other blocks' requests
	 * for queues and just allocate one RX queue.
	 *
	 * If RSS is enabled, then GGU has already informed the
	 * network configuration that it will be using a queue.
	 * The network configuration will crash if GGU doesn't
	 * configure that queue, so it still should, even if
	 * ntuple filter is not supported and GGU will not use it.
	 */

	if (ggu_conf->net->back.rss) {
		unsigned int num_mbuf = calculate_mempool_config_para("ggu",
			ggu_conf->net, ggu_conf->total_pkt_burst);

		ggu_conf->mp = create_pktmbuf_pool("ggu",
			ggu_conf->lcore_id, num_mbuf);
		if (ggu_conf->mp == NULL)
			return -1;

		ret = get_queue_id(&ggu_conf->net->back, QUEUE_TYPE_RX,
			ggu_conf->lcore_id, ggu_conf->mp);
		if (ret < 0) {
			G_LOG(ERR, "Cannot assign an RX queue for the back interface for lcore %u\n",
				ggu_conf->lcore_id);
			return ret;
		}
		ggu_conf->rx_queue_back = ret;
	}
	return 0;
}

static int
ggu_stage2(void *arg)
{
	struct ggu_config *ggu_conf = arg;
	int ret;

	/*
	 * Setup the filters that assign the GT-GK packets
	 * to its queue for both IPv4 and IPv6 addresses.
	 * Packets using the GGU protocol don't have variable
	 * length headers, and therefore we don't need a match
	 * function when calling ipv{4,6}_pkt_filter_add().
	 */

	if (ipv4_if_configured(&ggu_conf->net->back)) {
		/*
		 * Note that the IP address, ports, and masks
		 * are all in big endian ordering as required.
		 */
		ret = ipv4_pkt_filter_add(&ggu_conf->net->back,
			ggu_conf->net->back.ip4_addr.s_addr,
			ggu_conf->ggu_src_port, UINT16_MAX,
			ggu_conf->ggu_dst_port, UINT16_MAX,
			IPPROTO_UDP, ggu_conf->rx_queue_back,
			submit_ggu, NULL,
			&ggu_conf->rx_method_back);
		if (ret < 0) {
			G_LOG(ERR, "Could not configure IPv4 filter for GGU packets\n");
			return ret;
		}
	}

	if (ipv6_if_configured(&ggu_conf->net->back)) {
		/*
		 * Note that the IP address, ports, and masks
		 * are all in big endian ordering as required.
		 */
		ret = ipv6_pkt_filter_add(&ggu_conf->net->back,
			(rte_be32_t *)&ggu_conf->net->back.ip6_addr.s6_addr,
			ggu_conf->ggu_src_port, UINT16_MAX,
			ggu_conf->ggu_dst_port, UINT16_MAX,
			IPPROTO_UDP, ggu_conf->rx_queue_back,
			submit_ggu, NULL,
			&ggu_conf->rx_method_back);
		if (ret < 0) {
			G_LOG(ERR, "Could not configure IPv6 filter for GGU packets\n");
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
	uint16_t back_inc;

	if (ggu_conf == NULL || net_conf == NULL || gk_conf == NULL) {
		ret = -1;
		goto out;
	}

	if (!net_conf->back_iface_enabled) {
		G_LOG(ERR, "Back interface is required\n");
		ret = -1;
		goto out;
	}

	log_ratelimit_state_init(ggu_conf->lcore_id,
		ggu_conf->log_ratelimit_interval_ms,
		ggu_conf->log_ratelimit_burst,
		ggu_conf->log_level, "GGU");

	back_inc = ggu_conf->max_pkt_burst;
	net_conf->back.total_pkt_burst += back_inc;
	ggu_conf->total_pkt_burst = back_inc;

	ret = net_launch_at_stage1(net_conf, 0, 0, 1, 0, ggu_stage1, ggu_conf);
	if (ret < 0)
		goto burst;

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

	/*
	 * When mailbox is used for processing packets submitted by GK,
	 * it needs to make sure the packet burst size in the mailbox
	 * should be at least equal to the packet burst size in GK.
	 */
	ggu_conf->mailbox_max_pkt_burst = gk_conf->back_max_pkt_burst;

	ret = init_mailbox("ggu_mb", ggu_conf->mailbox_max_entries_exp,
		sizeof(struct ggu_request) + ggu_conf->mailbox_max_pkt_burst *
		sizeof(struct rte_mbuf *), ggu_conf->mailbox_mem_cache_size,
		ggu_conf->lcore_id, &ggu_conf->mailbox);
	if (ret < 0)
		goto put_gk;

	goto out;
put_gk:
	ggu_conf->gk = NULL;
	gk_conf_put(gk_conf);
/* stage3: */
	pop_n_at_stage3(1);
stage2:
	pop_n_at_stage2(1);
stage1:
	pop_n_at_stage1(1);
burst:
	net_conf->back.total_pkt_burst -= back_inc;
out:
	return ret;
}

/*
 * There should be only one ggu_config instance.
 * Return an error if trying to allocate the second instance.
 */
struct ggu_config *
alloc_ggu_conf(unsigned int lcore)
{
	static rte_atomic16_t num_ggu_conf_alloc = RTE_ATOMIC16_INIT(0);

	if (rte_atomic16_test_and_set(&num_ggu_conf_alloc) == 1) {
		ggu_conf = rte_calloc_socket("ggu_config", 1,
			sizeof(struct ggu_config), 0,
			rte_lcore_to_socket_id(lcore));
		if (ggu_conf == NULL) {
			rte_atomic16_clear(&num_ggu_conf_alloc);
			G_LOG(ERR,
				"Failed to allocate the first instance of struct ggu_config\n");
			return NULL;
		}
		ggu_conf->lcore_id = lcore;
		return ggu_conf;
	} else {
		G_LOG(ERR,
			"Trying to allocate the second instance of struct ggu_config\n");
		return NULL;
	}
}

int
cleanup_ggu(struct ggu_config *ggu_conf)
{
	destroy_mempool(ggu_conf->mp);
	destroy_mailbox(&ggu_conf->mailbox);
	ggu_conf->net = NULL;
	gk_conf_put(ggu_conf->gk);
	ggu_conf->gk = NULL;
	rte_free(ggu_conf);

	return 0;
}
