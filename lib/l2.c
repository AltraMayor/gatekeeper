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

#include "gatekeeper_l2.h"
#include "gatekeeper_main.h"

/*
 * Return the difference in the size of the L2 header between
 * packet received (@pkt) and a packet that will be transmitted
 * on @iface. This determines what changes have to be made to the
 * L2 space of the packet.
 *
 * A negative number indicates that bytes need to be removed from
 * the L2 space, and a positive number indicates that bytes need to
 * be added to the L2 space.
 *
 * WARNING
 *	Note that in order to use this function, @pkt must have first gone
 *	through pkt_in_skip_l2() or another function to set its packet type.
 */
static inline int
in_to_out_l2_diff(struct gatekeeper_if *iface, struct rte_mbuf *pkt)
{
	return iface->l2_len_out - pkt_in_l2_hdr_len(pkt);
}

/*
 * Adjust a packet's length.
 *
 * The parameter @bytes_to_add represents the number of bytes to add for higher
 * layers, if any, such as for an encapsulating network header. The function
 * then also takes into account how many bytes are necessary for the L2 header.
 * If @bytes_to_add is negative, bytes are removed from the packet.
 */
struct rte_ether_hdr *
adjust_pkt_len(struct rte_mbuf *pkt, struct gatekeeper_if *iface,
	int bytes_to_add)
{
	struct rte_ether_hdr *eth_hdr;

	bytes_to_add += in_to_out_l2_diff(iface, pkt);
	if (bytes_to_add > 0) {
		eth_hdr = (struct rte_ether_hdr *)rte_pktmbuf_prepend(pkt,
			bytes_to_add);
		if (eth_hdr == NULL) {
			G_LOG(ERR,
				"l2: not enough headroom space in the first segment\n");
			return NULL;
		}
	} else if (bytes_to_add < 0) {
		/*
		 * @bytes_to_add is negative, so its magnitude is
		 * the number of bytes we need to *remove*.
		 */
		eth_hdr = (struct rte_ether_hdr *)rte_pktmbuf_adj(pkt,
			-bytes_to_add);
		if (eth_hdr == NULL) {
			G_LOG(ERR, "l2: could not remove headroom space\n");
			return NULL;
		}
	} else
		eth_hdr = rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);

	return eth_hdr;
}

/*
 * Verify a packet's L2 header with respect to
 * the interface on which it was received.
 */
int
verify_l2_hdr(struct gatekeeper_if *iface, struct rte_ether_hdr *eth_hdr,
	uint32_t l2_type, const char *proto_name, uint16_t vlan_tag_be)
{
	if (iface->vlan_insert) {
		struct rte_vlan_hdr *vlan_hdr;

		/*
		 * Drop packets that don't have room for VLAN, since
		 * we would have to make space for a new header.
		 */
		if (unlikely(l2_type != RTE_PTYPE_L2_ETHER_VLAN)) {
			G_LOG(WARNING,
				"l2: %s interface incorrectly received an %s packet without a VLAN header\n",
				iface->name, proto_name);
			return -1;
		}

		/* Clear priority and CFI fields. */
		vlan_hdr = (struct rte_vlan_hdr *)&eth_hdr[1];
		RTE_BUILD_BUG_ON(!RTE_IS_POWER_OF_2(RTE_ETHER_MAX_VLAN_ID + 1));
		vlan_hdr->vlan_tci &= rte_cpu_to_be_16(RTE_ETHER_MAX_VLAN_ID);

		/* Drop packets whose VLAN tags are not correct. */
		if (unlikely(vlan_hdr->vlan_tci != vlan_tag_be)) {
			/*
			 * The log level below cannot be low due to
			 * loose filters in some vantage points, that is,
			 * Gatekeeper receives many packets for other VLANs
			 * during normal operation.
			 */
			G_LOG(INFO,
				"l2: %s interface received an %s packet with an incorrect VLAN tag (0x%02x but should be 0x%02x)\n",
				iface->name, proto_name,
				rte_be_to_cpu_16(vlan_hdr->vlan_tci),
				rte_be_to_cpu_16(vlan_tag_be));
			return -1;
		}
	} else if (unlikely(l2_type != RTE_PTYPE_UNKNOWN)) {
		/*
		 * Drop packets that have a VLAN header when we're not expecting
		 * one, since we would have to remove space in the header.
		 */
		G_LOG(WARNING,
			"l2: %s interface incorrectly received an %s packet with a VLAN header\n",
			iface->name, proto_name);
		return -1;
	}

	return 0;
}
