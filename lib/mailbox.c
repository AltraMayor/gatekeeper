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

#include <rte_log.h>
#include <rte_lcore.h>
#include <rte_debug.h>
#include <rte_malloc.h>

#include "gatekeeper_main.h"
#include "gatekeeper_mailbox.h"

/* XXX Sample parameters, need to be tested for better performance. */
#define GK_MEM_CACHE_SIZE (64)

int
init_mailbox(const char *tag, int mailbox_max_entries_exp, int ele_size,
	unsigned int lcore_id, struct mailbox *mb)
{
	int ret;
	char ring_name[128];
	char pool_name[128];
	unsigned int socket_id = rte_lcore_to_socket_id(lcore_id);

	ret = snprintf(ring_name,
		sizeof(ring_name), "%s_mailbox_ring_%u", tag, lcore_id);
	RTE_VERIFY(ret > 0 && ret < (int)sizeof(ring_name));

	mb->ring = (struct rte_ring *)rte_ring_create(
		ring_name, 1 << mailbox_max_entries_exp,
		socket_id, RING_F_SC_DEQ);
    	if (mb->ring == NULL) {
		RTE_LOG(ERR, RING,
			"mailbox: can't create ring %s (len = %d) at lcore %u!\n",
			ring_name, ret, lcore_id);
		ret = -1;
		goto out;
	}

	ret = snprintf(pool_name,
		sizeof(pool_name), "%s_mailbox_pool_%d", tag, lcore_id);
	RTE_VERIFY(ret > 0 && ret < (int)sizeof(pool_name));

    	mb->pool = (struct rte_mempool *)rte_mempool_create(
		pool_name, (1 << mailbox_max_entries_exp) - 1, ele_size,
		GK_MEM_CACHE_SIZE, 0, NULL, NULL, NULL, NULL, socket_id, 0);
    	if (mb->pool == NULL) {
		RTE_LOG(ERR, MEMPOOL,
			"mailbox: can't create mempool %s (len = %d) at lcore %u!\n",
			pool_name, ret, lcore_id);
		ret = -1;
        	goto free_ring;
    	}

	ret  = 0;
	goto out;

free_ring:
	rte_ring_free(mb->ring);
out:
	return ret;
}

void *
mb_alloc_entry(struct mailbox *mb)
{
	void *obj = NULL;
	int ret = rte_mempool_get(mb->pool, &obj);
	if (ret == -ENOENT) {
		RTE_LOG(ERR, MEMPOOL,
			"mailbox: not enough entries in the mempool.\n");
		return NULL;
	}

	RTE_VERIFY(ret == 0);

	return obj;
}

int
mb_send_entry(struct mailbox *mb, void *obj)
{
	int ret = rte_ring_mp_enqueue(mb->ring, obj);
	if (ret == -EDQUOT) {
		RTE_LOG(WARNING, RING,
			"mailbox: high water mark exceeded. The object has been enqueued.\n");
		ret = 0;
	} else if (ret == -ENOBUFS) {
		RTE_LOG(ERR, RING,
			"mailbox: quota exceeded. Not enough room in the ring to enqueue.\n");
		mb_free_entry(mb, obj);
	} else
		RTE_VERIFY(ret == 0);

	return ret;
}

void
destroy_mailbox(struct mailbox *mb)
{
	if (mb) {
		if (mb->ring)
    			rte_ring_free(mb->ring);
		if (mb->pool)
			rte_mempool_free(mb->pool);
	}
}
