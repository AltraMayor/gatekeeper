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

#include <arpa/inet.h>

#include <rte_thash.h>
#include <rte_debug.h>
#include <rte_ether.h>

#include "gatekeeper_net.h"
#include "gatekeeper_flow.h"
#include "gatekeeper_main.h"

/*
 * Optimized generic implementation of RSS hash function.
 * If you want the calculated hash value matches NIC RSS value,
 * you have to use special converted key with rte_convert_rss_key() fn.
 * @param input_tuple
 *   Pointer to input tuple with network order.
 * @param input_len
 *   Length of input_tuple in 4-bytes chunks.
 * @param *rss_key
 *   Pointer to RSS hash key.
 * @return
 *   Calculated hash value.
 */
static inline uint32_t
gk_softrss_be(const uint32_t *input_tuple, uint32_t input_len,
		const uint8_t *rss_key)
{
	uint32_t i;
	uint32_t j;
	uint32_t ret = 0;

	for (j = 0; j < input_len; j++) {
		/*
		 * Need to use little endian,
		 * since it takes ordering as little endian in both bytes and bits.
		 */
		uint32_t val = rte_be_to_cpu_32(input_tuple[j]);
		for (i = 0; i < 32; i++)
			if (val & (1 << (31 - i))) {
				/*
				 * The cast (uint64_t) is needed because when
				 * @i == 0, the expression requires a 32-bit
				 * shift of a 32-bit unsigned integer,
				 * what is undefined.
				 * The C standard only defines bit shifting
				 * up to the bit-size of the integer minus one.
				 * Finally, the cast (uint32_t) avoid promoting
				 * the expression before the bit-or (i.e. `|`)
				 * to uint64_t.
				 */
				ret ^= ((const uint32_t *)rss_key)[j] << i |
					(uint32_t)((uint64_t)
						(((const uint32_t *)rss_key)
							[j + 1])
						>> (32 - i));
			}
	}

	return ret;
}

uint32_t
rss_ip_flow_hf(const void *data,
	__attribute__((unused)) uint32_t data_len,
	__attribute__((unused)) uint32_t init_val)
{
	const struct ip_flow *flow = (const struct ip_flow *)data;

	if (flow->proto == RTE_ETHER_TYPE_IPV4)
		return gk_softrss_be((const uint32_t *)&flow->f,
				(sizeof(flow->f.v4)/sizeof(uint32_t)), rss_key_be);
	else if (flow->proto == RTE_ETHER_TYPE_IPV6)
		return gk_softrss_be((const uint32_t *)&flow->f,
				(sizeof(flow->f.v6)/sizeof(uint32_t)), rss_key_be);
	else
		rte_panic("Unexpected protocol: %i\n", flow->proto);

	return 0;
}

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

void
print_flow_err_msg(struct ip_flow *flow, const char *err_msg)
{
	char src[128];
	char dst[128];

	if (flow->proto == RTE_ETHER_TYPE_IPV4) {
		if (inet_ntop(AF_INET, &flow->f.v4.src,
				src, sizeof(src)) == NULL) {
			G_LOG(ERR, "flow: %s: failed to convert a number to an IPv4 address (%s)\n",
				__func__, strerror(errno));
			return;
		}

		if (inet_ntop(AF_INET, &flow->f.v4.dst,
				dst, sizeof(dst)) == NULL) {
			G_LOG(ERR, "flow: %s: failed to convert a number to an IPv4 address (%s)\n",
				__func__, strerror(errno));
			return;
		}
	} else if (likely(flow->proto == RTE_ETHER_TYPE_IPV6)) {
		if (inet_ntop(AF_INET6, flow->f.v6.src.s6_addr,
				src, sizeof(src)) == NULL) {
			G_LOG(ERR, "flow: %s: failed to convert a number to an IPv6 address (%s)\n",
				__func__, strerror(errno));
			return;
		}

		if (inet_ntop(AF_INET6, flow->f.v6.dst.s6_addr,
				dst, sizeof(dst)) == NULL) {
			G_LOG(ERR, "flow: %s: failed to convert a number to an IPv6 address (%s)\n",
				__func__, strerror(errno));
			return;
		}
	} else {
		G_LOG(ERR,
			"flow: %s; while trying to show flow data, an unknown flow type %hu was found\n",
			err_msg, flow->proto);
		return;
	}

	G_LOG(ERR,
		"flow: %s for the flow with IP source address %s, and destination address %s\n",
		err_msg, src, dst);
}
