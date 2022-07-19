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

#ifndef _GATEKEEPER_IPIP_H_
#define _GATEKEEPER_IPIP_H_

#include <rte_ether.h>

#include "gatekeeper_main.h"
#include "gatekeeper_flow.h"
#include "gatekeeper_net.h"

#define IP_VERSION              (0x40)
/* Default IP header length == five 32-bits words. */
#define IP_HDRLEN               (0x05)
/* From RFC 1340. */
#define IP_DEFTTL               (64)
#define IP_VHL_DEF              (IP_VERSION | IP_HDRLEN)
#define IP_DN_FRAGMENT_FLAG     (0x0040)

/*
 * Encapsulates the packet to send to Grantor with the given
 * priority. Adjusts the size of the Ethernet header, if
 * needed, for a VLAN header.
 */
int encapsulate(struct rte_mbuf *pkt, uint8_t priority,
	struct gatekeeper_if *iface, struct ipaddr *gt_addr);

#endif /* _GATEKEEPER_IPIP_H_ */
