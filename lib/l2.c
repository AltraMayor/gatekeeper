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
struct ether_hdr *
adjust_pkt_len(struct rte_mbuf *pkt, struct gatekeeper_if *iface,
	int bytes_to_add)
{
	struct ether_hdr *eth_hdr;

	bytes_to_add += in_to_out_l2_diff(iface, pkt);
	if (bytes_to_add > 0) {
		eth_hdr = (struct ether_hdr *)rte_pktmbuf_prepend(pkt,
			bytes_to_add);
		if (eth_hdr == NULL) {
			RTE_LOG(ERR, MBUF,
				"Not enough headroom space in the first segment!\n");
			return NULL;
		}
	} else if (bytes_to_add < 0) {
		/*
		 * @bytes_to_add is negative, so its magnitude is
		 * the number of bytes we need to *remove*.
		 */
		eth_hdr = (struct ether_hdr *)rte_pktmbuf_adj(pkt,
			-bytes_to_add);
		if (eth_hdr == NULL) {
			RTE_LOG(ERR, MBUF,
				"Could not remove headroom space!\n");
			return NULL;
		}
	} else
		eth_hdr = rte_pktmbuf_mtod(pkt, struct ether_hdr *);

	return eth_hdr;
}
