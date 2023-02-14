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

#ifndef _GATEKEEPER_GK_FIB_H_
#define _GATEKEEPER_GK_FIB_H_

#include <rte_atomic.h>

#include "gatekeeper_rib.h"

struct fib_tbl8 {
	rte_atomic32_t nh[0x100];
};

/* No-next-hop constant. */
#define FIB_NO_NH (0x7FFFFFFF)

#define FIB_TBL8_FREE_INDEX ((uint32_t)-1)

struct fib_head {
	/* RIB associated with the FIB. */
	struct rib_head rib;

	/* Length of address in bytes. */
	uint8_t         addr_len_bytes;

	/* Total number of allocated 8-bit tables. */
	uint32_t        num_tbl8s;

	/*
	 * Index of the first free 8-bit table in @tbl8_pool.
	 *
	 * If the pool is empty,
	 * tbl8_pool[first_free_tbl8_idx] == FIB_TBL8_FREE_INDEX.
	 */
	uint32_t	first_free_tbl8_idx;

	/*
	 * First free index in @tbl8_pool.
	 *
	 * If the pool is full,
	 * tbl8_pool[first_free_idx] != FIB_TBL8_FREE_INDEX.
	 */
	uint32_t        first_free_idx;

	/* Allocated 8-bit tables. */
	struct fib_tbl8 *tbl8s;

	/*
	 * Pool of free 8-bit tables.
	 *
	 * The pool is implemented from scratch as a circular list over
	 * an array to *practically* guarantee that freed 8-bit tables are
	 * always consistent, so there is no need to synchronize readers.
	 */
	uint32_t        *tbl8_pool;

	/* Table for the 24 most significative bits. */
	rte_atomic32_t  tbl24[0x1000000];
};

/*
 * Create a new FIB.
 *
 * @name is the prefix of the names of the internal memory pools.
 *
 * @socket_id is the NUMA node on which internal memory is allocated.
 * The value can be SOCKET_ID_ANY if there is no NUMA constraint.
 *
 * @max_length is the maximum length of a network address.
 * @max_length must be a multiple of 8, greater than or equal to 32, and
 * less than or equal to RIB_MAX_ADDRESS_LENGTH.
 * Typical values: 32 for IPv4 and 128 for IPv6.
 *
 * @max_rules is the maximum number of rules (i.e. a prefix and a next hop)
 * that this FIB is expected to have. If the FIB has space for more rules,
 * it will take extra rules. Inspite of the name, this parameter is meant
 * to mean the minimum number of rules that the FIB will support.
 *
 * @num_tbl8s is the number of TBL8s to be allocated.
 * @num_tbl8s must be less than FIB_TBL8_FREE_INDEX.
 * TBL8s are used for network prefixes that are longer than 24 bits.
 *
 */
int fib_create(struct fib_head *fib, const char *name, int socket_id,
	uint8_t max_length, uint32_t max_rules, uint32_t num_tbl8s);

/* Free all resources associated to @fib but the memory pointed by it. */
void fib_free(struct fib_head *fib);

/*
 * Return RIB associated to @fib.
 *
 * NOTE: Callers should only make read-only accesses to the returned RIB.
 */
static inline struct rib_head *fib_get_rib(struct fib_head *fib)
{
	return &fib->rib;
}

/* DO NOT CALL THIS FUNCTION, CALL fib_add() INSTEAD. */
int __fib_add(struct fib_head *fib, const uint8_t *address, uint8_t depth,
	uint32_t next_hop, bool failsafe);

/*
 * Add a rule to the FIB.
 *
 * @address is in network order (big endian).
 * @address == NULL is equivalent to the all-zero address.
 *
 * NOTES
 *	The most significant bit of @next_hop is not available.
 *
 *	The value FIB_NO_NH is reserved to designate that there is
 *	no next hop.
 *
 * RETURN
 *	-EINVAL if @next_hop >= FIB_NO_NH.
 * 	-EEXIST if prefix already exist in @fib.
 * 	0 if it successfully adds the new rule.
 */
static inline int
fib_add(struct fib_head *fib, const uint8_t *address, uint8_t depth,
	uint32_t next_hop)
{
	return __fib_add(fib, address, depth, next_hop, true);
}

/* DO NOT CALL THIS FUNCTION, CALL fib_add() INSTEAD. */
int __fib_delete(struct fib_head *fib, const uint8_t *address, uint8_t depth,
	bool failsafe);

/*
 * Delete a rule from the FIB.
 *
 * @address is in network order (big endian).
 * @address == NULL is equivalent to the all-zero address.
 *
 * RETURN
 * 	-ENOENT if the prefix does not exist in @fib.
 * 	0 if it successfully deletes the rule.
 */
static inline int
fib_delete(struct fib_head *fib, const uint8_t *address, uint8_t depth)
{
	return __fib_delete(fib, address, depth, true);
}

/*
 * Look an address up on the FIB.
 *
 * @address is in network order (big endian).
 * @address == NULL is equivalent to the all-zero address.
 *
 * The next hop of the longest rule for @address is saved in @pnext_hop.
 *
 * RETURN
 *	0 on lookup hit.
 *	-ENOENT on lookup miss.
 * 	A negative value on failure.
 */
int fib_lookup(const struct fib_head *fib, const uint8_t *address,
	uint32_t *pnext_hop);

/*
 * Look multiple addresses up on the FIB.
 *
 * Each @addresses[i] is in network order (big endian).
 * @addresses[i] == NULL is equivalent to the all-zero address.
 *
 * If the lookup of @addresses[i] fails, next_hops[i] = FIB_NO_NH.
 *
 * This function is an optimized version of the following code:
 *	unsigned int i;
 *	for (i = 0; i < n; i++)
 *		if (fib_lookup(fib, addresses[i], &next_hops[i]) != 0)
 *			next_hops[i] = FIB_NO_NH;
 */
void fib_lookup_bulk(const struct fib_head *fib, const uint8_t **addresses,
	uint32_t *next_hops, unsigned int n);

#endif /* _GATEKEEPER_GK_FIB_H_ */
