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

#ifndef _GATEKEEPER_VARIP_H_
#define _GATEKEEPER_VARIP_H_

#include <stdint.h>
#include <stdbool.h>

#include <rte_ip.h>

/*
 * All functional blocks that parse packets beyond the IP header
 * must be aware that variable IP headers are possible, and should
 * use the functionality provided by this library.
 */

static inline uint8_t
ipv4_hdr_len(struct rte_ipv4_hdr *ip4hdr)
{
	return ((ip4hdr->version_ihl & 0xf) << 2);
}

static inline uint8_t *
ipv4_skip_exthdr(struct rte_ipv4_hdr *ip4hdr)
{
	return ((uint8_t *)ip4hdr + ipv4_hdr_len(ip4hdr));
}

/*
 * Skip any extension headers.
 *
 * This function parses (potentially truncated) extension headers.
 * @nexthdrp should be a reference to the type of the header
 * that comes after the IPv6 header, which may or may not be
 * an IPv6 extension header.
 *
 * It skips all well-known exthdrs, and returns an offset to the start
 * of the unparsable area i.e. the first header with unknown type.
 * If it is not -1, *nexthdr is updated by type/protocol of this header.
 *
 * NOTES: - If packet terminated with NEXTHDR_NONE it returns -1.
 *        - If packet is truncated, so that all parsed headers are skipped,
 *	    it returns -1.
 *        - First fragment header is skipped, not-first ones
 *	    are considered as unparsable.
 *        - ESP is unparsable for now and considered like
 *	    normal payload protocol.
 */
int ipv6_skip_exthdr(const struct rte_ipv6_hdr *ip6hdr,
	int remaining_len, uint8_t *nexthdrp);

#endif /* _GATEKEEPER_VARIP_H_ */
