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

#ifndef _GATEKEEPER_FLOW_H_
#define _GATEKEEPER_FLOW_H_

#include <stdio.h>
#include <stdint.h>
#include <netinet/in.h>

struct ip_flow {
	/* IPv4 or IPv6. */
	uint16_t proto;

	union {
		struct {
			struct in_addr src;
			struct in_addr dst;
		} v4;

		struct {
			struct in6_addr src;
			struct in6_addr dst;
		} v6;
	} f;
};

int flow_cmp(const struct ip_flow *flow1, const struct ip_flow *flow2);

static inline bool
flow_equal(const struct ip_flow *flow1, const struct ip_flow *flow2)
{
	return flow_cmp(flow1, flow2) == 0;
}

void print_flow_err_msg(const struct ip_flow *flow, int32_t index,
	const char *err_msg);

#endif /* _GATEKEEPER_FLOW_H_ */
