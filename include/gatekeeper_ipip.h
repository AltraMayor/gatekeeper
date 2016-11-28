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

#ifndef _GATEKEEPER_IPIP_H_
#define _GATEKEEPER_IPIP_H_

#include <rte_ether.h>

#include "gatekeeper_flow.h"

struct ipip_tunnel_info {
	struct ip_flow	     flow;
	struct ether_addr    source_mac;
	/* TODO The MAC addresses must come from the LLS block. */
	struct ether_addr    nexthop_mac;
};

int encapsulate(struct rte_mbuf *pkt, uint8_t priority,
	struct ipip_tunnel_info *info);

#endif /* _GATEKEEPER_IPIP_H_ */
