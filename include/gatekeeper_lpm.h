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

#ifndef _GATEKEEPER_LPM_H_
#define _GATEKEEPER_LPM_H_

#include <rte_lpm.h>
#include <rte_lpm6.h>

/* TODO Implement functions to edit IPv4/IPv6 routes. */

/*
 * The API here aims to be general and allow developers
 * to create more than one LPM table on a single lcore id.
 * @lcore and @identifier are only used to differentiate instances.
 */
struct rte_lpm *init_ipv4_lpm(const char *tag,
	const struct rte_lpm_config *lpm_conf,
	unsigned int socket_id, unsigned int lcore, unsigned int identifier);
int lpm_lookup_ipv4(struct rte_lpm *lpm, uint32_t ip);

/* Similar to init_ipv4_lpm(), see above. */
struct rte_lpm6 *init_ipv6_lpm(const char *tag,
	const struct rte_lpm6_config *lpm6_conf,
	unsigned int socket_id, unsigned int lcore, unsigned int identifier);
int lpm_lookup_ipv6(struct rte_lpm6 *lpm, uint8_t *ip);

static inline void
destroy_ipv4_lpm(struct rte_lpm *lpm)
{
	rte_lpm_free(lpm);
}

static inline void
destroy_ipv6_lpm(struct rte_lpm6 *lpm)
{
	rte_lpm6_free(lpm);
}

#endif /* _GATEKEEPER_LPM_H_ */
