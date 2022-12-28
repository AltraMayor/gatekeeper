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

#include <rte_malloc.h>

#include "gatekeeper_main.h"
#include "gatekeeper_fib.h"

static inline void
write_atomics(rte_atomic32_t *array, uint32_t first, uint32_t last, int val)
{
	uint32_t i;
	for (i = first; i <= last; i++)
		rte_atomic32_set(&array[i], val);
}

int
fib_create(struct fib_head *fib, const char *name, int socket_id,
	uint8_t max_length, uint32_t max_rules, uint32_t num_tbl8s)
{
	char rib_name[256], tbl8s_name[256], pool_name[256];
	int ret;
	uint32_t i;

	/*
	 * Check input.
	 */

	if (unlikely(max_length % 8 != 0)) {
		G_LOG(ERR, "%s(): max_length=%u is not a multiple of 8\n",
			__func__, max_length);
		return -EINVAL;
	}

	/*
	 * Having max_length >= 32 guarantees that there's at least one level
	 * of tbl8s. This assumption simplifies the code that implements
	 * fib_add() and fib_del().
	 */
	if (unlikely(max_length < 32 || RIB_MAX_ADDRESS_LENGTH < max_length)) {
		G_LOG(ERR, "%s(): max_length=%u must be in [32, %u]\n",
			__func__, max_length, RIB_MAX_ADDRESS_LENGTH);
		return -EINVAL;
	}

	if (unlikely(max_rules == 0)) {
		G_LOG(ERR, "%s(): max_rules=%u must be greater than zero\n",
			__func__, max_rules);
		return -EINVAL;
	}

	if (unlikely(num_tbl8s == 0 || num_tbl8s >= FIB_TBL8_FREE_INDEX)) {
		G_LOG(ERR, "%s(): num_tbl8s=%u must be in [0, %u)\n",
			__func__, num_tbl8s, FIB_TBL8_FREE_INDEX);
		return -EINVAL;
	}

	ret = snprintf(rib_name, sizeof(rib_name), "%s_RIB", name);
	if (unlikely(ret <= 0 || ret >= (int)sizeof(rib_name))) {
		G_LOG(ERR, "%s(rib_name): name=`%s' is too long\n",
			__func__, name);
		return -EINVAL;
	}

	ret = snprintf(tbl8s_name, sizeof(tbl8s_name), "%s_TBL8s", name);
	if (unlikely(ret <= 0 || ret >= (int)sizeof(tbl8s_name))) {
		G_LOG(ERR, "%s(tbl8s_name): name=`%s' is too long\n",
			__func__, name);
		return -EINVAL;
	}

	ret = snprintf(pool_name, sizeof(pool_name), "%s_TBL8s_pool", name);
	if (unlikely(ret <= 0 || ret >= (int)sizeof(pool_name))) {
		G_LOG(ERR, "%s(pool_name): name=`%s' is too long\n",
			__func__, name);
		return -EINVAL;
	}

	/*
	 * Initialize internal RIB.
	 */

	ret = rib_create(&fib->rib, rib_name, socket_id, max_length, max_rules);
	if (unlikely(ret < 0)) {
		G_LOG(ERR, "%s(): failed to create RIB %s\n",
			__func__, rib_name);
		goto out;
	}
	fib->addr_len_bytes = max_length / 8;

	/*
	 * Initialize 8-bit tables.
	 */

	fib->tbl8s = rte_malloc_socket(tbl8s_name,
		sizeof(*fib->tbl8s) * num_tbl8s, 0, socket_id);
	if (unlikely(fib->tbl8s == NULL)) {
		ret = -ENOMEM;
		goto free_rib;
	}

	fib->num_tbl8s = num_tbl8s;
	for (i = 0; i < num_tbl8s; i++) {
		write_atomics(fib->tbl8s[i].nh,
			0, RTE_DIM(fib->tbl8s[i].nh) - 1, FIB_NO_NH);
	}

	/*
	 * Initialize pool of 8-bit tables.
	 */

	fib->tbl8_pool = rte_malloc_socket(pool_name,
		sizeof(*fib->tbl8_pool) * num_tbl8s, 0, socket_id);
	if (unlikely(fib->tbl8_pool == NULL)) {
		ret = -ENOMEM;
		goto free_tbl8s;
	}

	fib->first_free_tbl8_idx = 0;
	fib->first_free_idx = 0;
	for (i = 0; i < num_tbl8s; i++)
		fib->tbl8_pool[i] = i;

	/* Initialize 24-bit table. */
	write_atomics(fib->tbl24, 0, RTE_DIM(fib->tbl24) - 1, FIB_NO_NH);

	return 0;

free_tbl8s:
	rte_free(fib->tbl8s);
	fib->tbl8s = NULL;
free_rib:
	rib_free(&fib->rib);
out:
	return ret;
}

void
fib_free(struct fib_head *fib)
{
	fib->tbl8_pool[0] = FIB_TBL8_FREE_INDEX;
	fib->first_free_tbl8_idx = 0;
	fib->first_free_idx = 0;
	rte_free(fib->tbl8_pool);
	fib->tbl8_pool = NULL;

	fib->num_tbl8s = 0;
	rte_free(fib->tbl8s);
	fib->tbl8s = NULL;

	rib_free(&fib->rib);
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
