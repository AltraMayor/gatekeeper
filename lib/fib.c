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

#include "gatekeeper_fib.h"

int
fib_create(struct fib_head *fib, const char *name, int socket_id,
	uint8_t max_length, uint32_t max_rules, uint32_t num_tbl8s)
{
	/* TODO */
	RTE_SET_USED(fib);
	RTE_SET_USED(name);
	RTE_SET_USED(socket_id);
	RTE_SET_USED(max_length);
	RTE_SET_USED(max_rules);
	RTE_SET_USED(num_tbl8s);
	return -ENOTSUP;
}

void
fib_free(struct fib_head *fib)
{
	/* TODO */
	RTE_SET_USED(fib);
}

int
fib_add(struct fib_head *fib, const uint8_t *address, uint8_t depth,
	uint32_t next_hop)
{
	/* TODO */
	RTE_SET_USED(fib);
	RTE_SET_USED(address);
	RTE_SET_USED(depth);
	RTE_SET_USED(next_hop);
	return -ENOTSUP;
}

int
fib_delete(struct fib_head *fib, const uint8_t *address, uint8_t depth)
{
	/* TODO */
	RTE_SET_USED(fib);
	RTE_SET_USED(address);
	RTE_SET_USED(depth);
	return -ENOTSUP;
}

int fib_lookup(const struct fib_head *fib, const uint8_t *address,
	uint32_t *pnext_hop)
{
	/* TODO */
	RTE_SET_USED(fib);
	RTE_SET_USED(address);
	RTE_SET_USED(pnext_hop);
	return -ENOTSUP;
}

void
fib_lookup_bulk(const struct fib_head *fib, const uint8_t **addresses,
	uint32_t *next_hops, unsigned int n)
{
	/* TODO */
	RTE_SET_USED(fib);
	RTE_SET_USED(addresses);
	RTE_SET_USED(next_hops);
	RTE_SET_USED(n);
}
