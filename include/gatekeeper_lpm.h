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

#ifndef _GATEKEEPER_LPM_H_
#define _GATEKEEPER_LPM_H_

#include <rte_lpm6.h>
#include <string.h>

#include <rte_fib.h>
#include <rte_byteorder.h>

/*
 * RTE_FIB_DIR24_8_4B allocates 4 bytes minus one bit for the next hop, so
 * the maximum value is 31 bits. This is important because the rte_fib and
 * rte_fib6 trucates the value of the default hop to this size.
 */
#define LPM_DEFAULT_NH (0x7FFFFFFF)

static inline void
set_ipv4_lpm_conf(struct rte_fib_conf *conf, uint32_t max_routes,
	uint32_t num_tbl8)
{
	memset(conf, 0, sizeof(*conf));
	conf->type = RTE_FIB_DIR24_8;
	conf->default_nh = LPM_DEFAULT_NH;
	conf->max_routes = max_routes;
	conf->dir24_8.nh_sz = RTE_FIB_DIR24_8_4B;
	conf->dir24_8.num_tbl8 = num_tbl8;
}

/*
 * The API here aims to be general and allow developers
 * to create more than one LPM table on a single lcore id.
 * @lcore and @identifier are only used to differentiate instances.
 *
 * The parameter lpm_conf is passed by copy because rte_fib_create(),
 * which receives the parameter, does not have a const qualifier for it.
 */
struct rte_fib *init_ipv4_lpm(const char *tag, struct rte_fib_conf lpm_conf,
	unsigned int socket_id, unsigned int lcore, unsigned int identifier);
int lpm_lookup_ipv4(struct rte_fib *lpm, uint32_t ip);

/* @ip is in network order (i.e. big endian). */
static inline int
lpm_add(struct rte_fib *fib, uint32_t ip, uint8_t depth, uint64_t next_hop)
{
	return rte_fib_add(fib, rte_be_to_cpu_32(ip), depth, next_hop);
}

/* @ip is in network order (i.e. big endian). */
static inline int
lpm_delete(struct rte_fib *fib, uint32_t ip, uint8_t depth)
{
	return rte_fib_delete(fib, rte_be_to_cpu_32(ip), depth);
}

static inline void
destroy_ipv4_lpm(struct rte_fib *lpm)
{
	rte_fib_free(lpm);
}

/* Similar to init_ipv4_lpm(), see above. */
struct rte_lpm6 *init_ipv6_lpm(const char *tag,
	const struct rte_lpm6_config *lpm6_conf,
	unsigned int socket_id, unsigned int lcore, unsigned int identifier);
int lpm_lookup_ipv6(struct rte_lpm6 *lpm, struct in6_addr *ip);

static inline void
destroy_ipv6_lpm(struct rte_lpm6 *lpm)
{
	rte_lpm6_free(lpm);
}

#endif /* _GATEKEEPER_LPM_H_ */
