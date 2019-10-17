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

#include <netinet/ip.h>

#include <rte_ip.h>
#include <rte_mbuf.h>
#include <rte_memcpy.h>
#include <rte_byteorder.h>

#include "gatekeeper_ipip.h"
#include "gatekeeper_l2.h"

/*
 * The Full-functionality Option for setting ECN bits in IP-in-IP packets.
 * RFC 3168, section 9.1.1.
 *
 * If the ECN codepoint of the inside header is CE, set the ECN codepoint of
 * the outside header to ECT(0). Otherwise (the inside ECN is not-ECT or ECT),
 * copy the ECN codepoint of the inside header to the outside header.
 */
static inline uint8_t in_to_out_ecn(uint8_t inner_tos)
{
	return (inner_tos & IPTOS_ECN_MASK) == IPTOS_ECN_CE
		? IPTOS_ECN_ECT0
		: inner_tos & IPTOS_ECN_MASK;
}

int
encapsulate(struct rte_mbuf *pkt, uint8_t priority,
	struct gatekeeper_if *iface, struct ipaddr *gt_addr)
{
	struct rte_ether_hdr *eth_hdr;
	struct rte_ipv4_hdr *outer_ip4hdr;
	struct rte_ipv6_hdr *outer_ip6hdr;

	if (gt_addr->proto == RTE_ETHER_TYPE_IPV4) {
		struct rte_ipv4_hdr *inner_ip4hdr;

		/* Allocate space for outer IPv4 header and L2 header. */
		eth_hdr = adjust_pkt_len(pkt,
			iface, sizeof(struct rte_ipv4_hdr));
		if (eth_hdr == NULL) {
			G_LOG(ERR, "ipip: could not adjust IPv4 packet length\n");
			return -1;
		}

		outer_ip4hdr = pkt_out_skip_l2(iface, eth_hdr);
		inner_ip4hdr = (struct rte_ipv4_hdr *)&outer_ip4hdr[1];

		/* Fill up the outer IP header. */
		outer_ip4hdr->version_ihl = IP_VHL_DEF;
		outer_ip4hdr->type_of_service = (priority << 2) |
			in_to_out_ecn(inner_ip4hdr->type_of_service);
		outer_ip4hdr->packet_id = 0;
		outer_ip4hdr->fragment_offset = IP_DN_FRAGMENT_FLAG;
		outer_ip4hdr->time_to_live = IP_DEFTTL;
		outer_ip4hdr->next_proto_id = IPPROTO_IPIP;
		/* The source address is the Gatekeeper server IP address. */
		outer_ip4hdr->src_addr = iface->ip4_addr.s_addr;
		/* The destination address is the Grantor server IP address. */
		outer_ip4hdr->dst_addr = gt_addr->ip.v4.s_addr;

		outer_ip4hdr->total_length =
			rte_cpu_to_be_16(pkt->pkt_len - iface->l2_len_out);

		/*
		 * The IP header checksum filed must be set to 0
		 * in order to offload the checksum calculation.
		 */
		outer_ip4hdr->hdr_checksum = 0;

		pkt->l3_len = sizeof(struct rte_ipv4_hdr);
		/* Offload checksum computation for the outer IPv4 header. */
		pkt->ol_flags |= (PKT_TX_IPV4 | PKT_TX_IP_CKSUM);
	} else if (likely(gt_addr->proto == RTE_ETHER_TYPE_IPV6)) {
		struct rte_ipv6_hdr *inner_ip6hdr;

		/* Allocate space for new IPv6 header and L2 header. */
		eth_hdr = adjust_pkt_len(pkt,
			iface, sizeof(struct rte_ipv6_hdr));
		if (eth_hdr == NULL) {
			G_LOG(ERR, "ipip: could not adjust IPv6 packet length\n");
			return -1;
		}

		outer_ip6hdr = pkt_out_skip_l2(iface, eth_hdr);
		inner_ip6hdr = (struct rte_ipv6_hdr *)&outer_ip6hdr[1];

		/* Fill up the outer IP header. */
		outer_ip6hdr->vtc_flow = rte_cpu_to_be_32(
			IPv6_DEFAULT_VTC_FLOW | (priority << 22) |
			(in_to_out_ecn(rte_be_to_cpu_32(
				inner_ip6hdr->vtc_flow) >> 20) << 20));
		outer_ip6hdr->proto = IPPROTO_IPV6;
		outer_ip6hdr->hop_limits = iface->ipv6_default_hop_limits;

		rte_memcpy(outer_ip6hdr->src_addr, iface->ip6_addr.s6_addr,
			sizeof(outer_ip6hdr->src_addr));
		rte_memcpy(outer_ip6hdr->dst_addr, gt_addr->ip.v6.s6_addr,
			sizeof(outer_ip6hdr->dst_addr));

		outer_ip6hdr->payload_len = rte_cpu_to_be_16(pkt->pkt_len
			- (sizeof(struct rte_ipv6_hdr) + iface->l2_len_out));
	} else 
		return -1;

	return 0;
}
