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

#ifndef _GATEKEEPER_L2_H_
#define _GATEKEEPER_L2_H_

#include <rte_ether.h>
#include <rte_mbuf.h>
#include <rte_mbuf_ptype.h>

#include "gatekeeper_main.h"
#include "gatekeeper_net.h"

#define ETHERNET_II_ETHERTYPES (0x0600)

static inline void
log_unknown_l2(const char *name, uint16_t ether_type)
{
	/*
	 * If this field is >= 0x0600, it is an EtherType
	 * field from the Ethernet II standard.
	 *
	 * If this field is <= 0x05DC, it is a length
	 * field from the 802.3 standard. Any other
	 * value is invalid. We only log this when in
	 * debug mode.
	 */
	if (ether_type < ETHERNET_II_ETHERTYPES) {
		RTE_LOG(DEBUG, GATEKEEPER,
			"%s: invalid Ethernet field or frame not Ethernet II:%" PRIu16 "!\n",
			name, ether_type);
	} else {
		RTE_LOG(NOTICE, GATEKEEPER,
			"%s: unknown EtherType %" PRIu16 "!\n",
			name, ether_type);
	}
}

/*
 * Return the L2 header length of a received packet.
 *
 * WARNING
 *	Note that in order to use this function, @pkt must have first gone
 *	through pkt_in_skip_l2() or another function to set its packet type.
 */
static inline size_t
pkt_in_l2_hdr_len(struct rte_mbuf *pkt)
{
	return pkt->l2_type != RTE_PTYPE_L2_ETHER_VLAN
		? sizeof(struct ether_hdr)
		: sizeof(struct ether_hdr) + sizeof(struct vlan_hdr);
}

/*
 * Skip the L2 header of the packet, skipping over any VLAN
 * headers if present. A pointer to the next header is returned.
 */
static inline void *
pkt_out_skip_l2(struct gatekeeper_if *iface, struct ether_hdr *eth_hdr)
{
	return ((uint8_t *)eth_hdr) + iface->l2_len_out;
}

/*
 * Skip the L2 header of the packet, skipping over any VLAN
 * headers if present. The EtherType of the next header is returned
 * (in network order).
 */
static inline uint16_t
pkt_in_skip_l2(struct rte_mbuf *pkt, struct ether_hdr *eth_hdr, void **next_hdr)
{
	RTE_VERIFY(next_hdr != NULL);

	if (likely(eth_hdr->ether_type != rte_cpu_to_be_16(ETHER_TYPE_VLAN))) {
		*next_hdr = &eth_hdr[1];
		pkt->l2_type = RTE_PTYPE_UNKNOWN;
		return eth_hdr->ether_type;
	} else {
		struct vlan_hdr *vlan_hdr = (struct vlan_hdr *)&eth_hdr[1];
		*next_hdr = &vlan_hdr[1];
		pkt->l2_type = RTE_PTYPE_L2_ETHER_VLAN;
		return vlan_hdr->eth_proto;
	}
}

/*
 * Given an Ethernet header and room to put a VLAN header,
 * set the EtherType field and the VLAN header fields
 * using the given VLAN tag.
 */
static inline void
fill_vlan_hdr(struct ether_hdr *eth_hdr, uint16_t vlan_tag_be,
	uint16_t eth_proto)
{
	struct vlan_hdr *vlan_hdr = (struct vlan_hdr *)&eth_hdr[1];
	eth_hdr->ether_type = rte_cpu_to_be_16(ETHER_TYPE_VLAN);
	vlan_hdr->vlan_tci = vlan_tag_be;
	vlan_hdr->eth_proto = rte_cpu_to_be_16(eth_proto);
}

struct ether_hdr *adjust_pkt_len(struct rte_mbuf *pkt,
	struct gatekeeper_if *iface, int bytes_to_add);

int verify_l2_hdr(struct gatekeeper_if *iface, struct ether_hdr *eth_hdr,
	uint32_t l2_type, const char *proto_name);

#endif /* _GATEKEEPER_L2_H_ */
