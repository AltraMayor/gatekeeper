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

#ifndef _GATEKEEPER_MAILBOX_H_
#define _GATEKEEPER_MAILBOX_H_

#include <rte_ring.h>
#include <rte_mempool.h>

#include "gatekeeper_main.h"

struct mailbox {
	struct rte_ring    *ring;
	struct rte_mempool *pool;
};

/*
 * For optimum memory usage, the maximum number of elements for
 * rte_ring_create() is defined as (2^mailbox_max_entries_exp), while
 * the maximum number of elements for rte_mempool_create() is
 * defined as (2^mailbox_max_entries_exp - 1).
 */
int init_mailbox(
	const char *tag, int mailbox_max_entries_exp,
	unsigned int ele_size, unsigned int cache_size,
	unsigned int lcore_id, struct mailbox *mb);
void *mb_alloc_entry(struct mailbox *mb);
int mb_send_entry(struct mailbox *mb, void *obj);
void destroy_mailbox(struct mailbox *mb);

static inline int
mb_dequeue_burst(struct mailbox *mb, void **obj_table, unsigned n)
{
	return rte_ring_sc_dequeue_burst(mb->ring, obj_table, n, NULL);
}

static inline void
mb_free_entry(struct mailbox *mb, void *obj)
{
	rte_mempool_put(mb->pool, obj);
}

#endif /* _GATEKEEPER_MAILBOX_H_ */
