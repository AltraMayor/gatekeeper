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

#ifndef _GATEKEEPER_LLS_ARP_H_
#define _GATEKEEPER_LLS_ARP_H_

#include "gatekeeper_lls.h"
#include "gatekeeper_net.h"

/* Whether ARP is enabled on this interface. */
int iface_arp_enabled(struct net_config *net, struct gatekeeper_if *iface);

/* Convert @ip_be to an IPv4 address and store it in @buf. */
char *ipv4_str(struct lls_cache *cache, const uint8_t *ip_be,
	char *buf, size_t len);

/* Return whether @ip_be is in the same subnet as @iface's IPv4 address. */
int ipv4_in_subnet(struct gatekeeper_if *iface, const void *ip_be);

/* Transmit an ARP request packet. */
void xmit_arp_req(struct gatekeeper_if *iface, const uint8_t *ip_be,
	const struct ether_addr *ha, uint16_t tx_queue);

/*
 * Process an ARP packet that arrived on @iface.
 *
 * Returns 0 if the packet was transmitted (and already freed),
 * -1 if it does not need to be transmitted (and needs to be freed).
 */
int process_arp(struct lls_config *lls_conf, struct gatekeeper_if *iface,
	uint16_t tx_queue, struct rte_mbuf *buf, struct ether_hdr *eth_hdr);

/* Print an ARP record. */
void print_arp_record(struct lls_cache *cache, struct lls_record *record);

#endif /* _GATEKEEPER_LLS_ARP_H_ */
