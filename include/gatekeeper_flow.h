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

#ifndef _GATEKEEPER_FLOW_H_
#define _GATEKEEPER_FLOW_H_

#include <stdio.h>
#include <stdint.h>

struct ip_flow {
	/* IPv4 or IPv6. */
	uint16_t proto;

	union {
		struct {
			uint32_t src;
			uint32_t dst;
		} v4;

		struct {
			uint8_t src[16];
			uint8_t dst[16];
		} v6;
	} f;
};

uint32_t rss_ip_flow_hf(const void *data,
	uint32_t data_len, uint32_t init_val);

int ip_flow_cmp_eq(const void *key1, const void *key2, size_t key_len);

void print_flow_err_msg(struct ip_flow *flow, const char *err_msg);

#endif /* _GATEKEEPER_FLOW_H_ */
