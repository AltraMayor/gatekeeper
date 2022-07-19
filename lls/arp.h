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

#ifndef _GATEKEEPER_LLS_ARP_H_
#define _GATEKEEPER_LLS_ARP_H_

#include "gatekeeper_lls.h"
#include "gatekeeper_net.h"

/* Whether ARP is enabled on this interface. */
int iface_arp_enabled(struct net_config *net, struct gatekeeper_if *iface);

/* Return whether @addr is in the same subnet as @iface's IPv4 address. */
int ipv4_in_subnet(struct gatekeeper_if *iface, const struct ipaddr *addr);

/* Transmit an ARP request packet. */
void xmit_arp_req(struct gatekeeper_if *iface, const struct ipaddr *addr,
	const struct rte_ether_addr *ha, uint16_t tx_queue);

/*
 * Process an ARP packet that arrived on @iface.
 *
 * Returns 0 if the packet was transmitted (and already freed),
 * -1 if it does not need to be transmitted (and needs to be freed).
 */
int process_arp(struct lls_config *lls_conf, struct gatekeeper_if *iface,
	uint16_t tx_queue, struct rte_mbuf *buf, struct rte_ether_hdr *eth_hdr,
	struct rte_arp_hdr *arp_hdr);

#endif /* _GATEKEEPER_LLS_ARP_H_ */
