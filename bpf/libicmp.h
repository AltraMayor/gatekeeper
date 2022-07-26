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

#ifndef _LIBICMP_H_
#define _LIBICMP_H_

#include <net/ethernet.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>

#include <rte_mbuf_core.h>

#include "gatekeeper_flow_bpf.h"

static inline uint64_t
check_icmp(struct gk_bpf_pkt_ctx *ctx, struct rte_mbuf *pkt)
{
	struct icmphdr *icmp_hdr;

	if (unlikely(ctx->l3_proto != ETHERTYPE_IP)) {
		/* ICMP must be on top of IPv4. */
		return GK_BPF_PKT_RET_DECLINE;
	}
	if (ctx->fragmented)
		return GK_BPF_PKT_RET_DECLINE;
	if (unlikely(pkt->l4_len < sizeof(*icmp_hdr))) {
		/* Malformed ICMP header. */
		return GK_BPF_PKT_RET_DECLINE;
	}
	icmp_hdr = rte_pktmbuf_mtod_offset(pkt, struct icmphdr *,
		pkt->l2_len + pkt->l3_len);
	switch (icmp_hdr->type) {
	case ICMP_ECHOREPLY:
	case ICMP_DEST_UNREACH:
	case ICMP_SOURCE_QUENCH:
	case ICMP_ECHO:
	case ICMP_TIME_EXCEEDED:
		break;
	default:
		return GK_BPF_PKT_RET_DECLINE;
	}

	return GK_BPF_PKT_RET_FORWARD;
}

static inline uint64_t
check_icmp6(struct gk_bpf_pkt_ctx *ctx, struct rte_mbuf *pkt)
{
	struct icmp6_hdr *icmp6_hdr;

	if (unlikely(ctx->l3_proto != ETHERTYPE_IPV6)) {
		/* ICMPv6 must be on top of IPv6. */
		return GK_BPF_PKT_RET_DECLINE;
	}
	if (ctx->fragmented)
		return GK_BPF_PKT_RET_DECLINE;
	if (unlikely(pkt->l4_len < sizeof(*icmp6_hdr))) {
		/* Malformed ICMPv6 header. */
		return GK_BPF_PKT_RET_DECLINE;
	}
	icmp6_hdr = rte_pktmbuf_mtod_offset(pkt, struct icmp6_hdr *,
		pkt->l2_len + pkt->l3_len);
	switch (icmp6_hdr->icmp6_type) {
	case ICMP6_DST_UNREACH:
	case ICMP6_PACKET_TOO_BIG:
	case ICMP6_TIME_EXCEEDED:
	case ICMP6_PARAM_PROB:
	case ICMP6_ECHO_REQUEST:
	case ICMP6_ECHO_REPLY:
		break;
	default:
		return GK_BPF_PKT_RET_DECLINE;
	}

	return GK_BPF_PKT_RET_FORWARD;
}

#endif /* _LIBICMP_H_ */
