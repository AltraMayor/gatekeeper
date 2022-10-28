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

#include <arpa/inet.h>

#include <rte_thash.h>
#include <rte_debug.h>
#include <rte_ether.h>

#include "gatekeeper_net.h"
#include "gatekeeper_main.h"
#include "gatekeeper_flow.h"

/* Type of function used to compare the hash key. */
int
ip_flow_cmp_eq(const void *key1, const void *key2,
	__attribute__((unused)) size_t key_len)
{
	const struct ip_flow *f1 = (const struct ip_flow *)key1;
	const struct ip_flow *f2 = (const struct ip_flow *)key2;

	if (f1->proto != f2->proto)
		return f1->proto == RTE_ETHER_TYPE_IPV4 ? -1 : 1;

	if (f1->proto == RTE_ETHER_TYPE_IPV4)
		return memcmp(&f1->f.v4, &f2->f.v4, sizeof(f1->f.v4));
	else
		return memcmp(&f1->f.v6, &f2->f.v6, sizeof(f1->f.v6));
}

static void
print_invalid_flow_err_msg(const struct ip_flow *flow, const char *index_str,
	const char *err_msg)
{
	const uint64_t *src = (const uint64_t *)&flow->f.v6.src;
	const uint64_t *dst = (const uint64_t *)&flow->f.v6.dst;

	RTE_BUILD_BUG_ON(sizeof(flow->f.v6.src) != 16);
	RTE_BUILD_BUG_ON(sizeof(flow->f.v6.dst) != 16);

	G_LOG(ERR, "INVALID Flow {proto = %i, f.v6.src = 0x%016"PRIx64
		"%016"PRIx64", f.v6.dst = 0x%016"PRIx64"%016"PRIx64"}%s: %s\n",
		flow->proto,
		rte_be_to_cpu_64(src[0]), rte_be_to_cpu_64(src[1]),
		rte_be_to_cpu_64(dst[0]), rte_be_to_cpu_64(dst[1]),
		index_str, err_msg);
}

#define INVALID_IP_ADDR_STRING "<ERROR>"

void
print_flow_err_msg(const struct ip_flow *flow, int32_t index,
	const char *err_msg)
{
	char src[INET6_ADDRSTRLEN];
	char dst[INET6_ADDRSTRLEN];
	char index_str[64];
	int ret;

	RTE_BUILD_BUG_ON(INET6_ADDRSTRLEN < INET_ADDRSTRLEN);
	RTE_BUILD_BUG_ON(sizeof(src) < sizeof(INVALID_IP_ADDR_STRING));
	RTE_BUILD_BUG_ON(sizeof(dst) < sizeof(INVALID_IP_ADDR_STRING));

	if (unlikely(!G_LOG_CHECK(ERR)))
		return;

	/* Fill @index_str out. */
	if (index >= 0) {
		ret = snprintf(index_str, sizeof(index_str), " at index %i",
			index);
		RTE_VERIFY(ret > 0 && ret < (int)sizeof(index_str));
	} else if (likely(index == -ENOENT)) {
		/* Empty string. */
		index_str[0] = '\0';
	} else {
		ret = snprintf(index_str, sizeof(index_str),
			" error index (%i)", -index);
		RTE_VERIFY(ret > 0 && ret < (int)sizeof(index_str));
	}

	if (flow->proto == RTE_ETHER_TYPE_IPV4) {
		if (unlikely(inet_ntop(AF_INET, &flow->f.v4.src,
				src, sizeof(src)) == NULL)) {
			G_LOG(ERR, "%s(): failed to convert source IPv4 address to a string (errno=%i): %s\n",
				__func__, errno, strerror(errno));
			strcpy(src, INVALID_IP_ADDR_STRING);
		}

		if (unlikely(inet_ntop(AF_INET, &flow->f.v4.dst,
				dst, sizeof(dst)) == NULL)) {
			G_LOG(ERR, "%s(): failed to convert destination IPv4 address to a string (errno=%i): %s\n",
				__func__, errno, strerror(errno));
			strcpy(dst, INVALID_IP_ADDR_STRING);
		}
	} else if (likely(flow->proto == RTE_ETHER_TYPE_IPV6)) {
		if (unlikely(inet_ntop(AF_INET6, flow->f.v6.src.s6_addr,
				src, sizeof(src)) == NULL)) {
			G_LOG(ERR, "%s(): failed to convert source IPv6 address to a string (errno=%i): %s\n",
				__func__, errno, strerror(errno));
			strcpy(src, INVALID_IP_ADDR_STRING);
		}

		if (unlikely(inet_ntop(AF_INET6, flow->f.v6.dst.s6_addr,
				dst, sizeof(dst)) == NULL)) {
			G_LOG(ERR, "%s(): failed to convert destination IPv6 address to a string (errno=%i): %s\n",
				__func__, errno, strerror(errno));
			strcpy(dst, INVALID_IP_ADDR_STRING);
		}
	} else {
		return print_invalid_flow_err_msg(flow, index_str, err_msg);
	}

	G_LOG(ERR, "Flow (src: %s, dst: %s)%s: %s\n", src, dst,
		index_str, err_msg);
}
