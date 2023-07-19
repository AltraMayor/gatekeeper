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
#include "gatekeeper_qid.h"

/*
 * *Q*uick *Id*entifiers library.
 *
 * A LIFO stack of consecutive IDs. One use case is that the
 * stack holds the available indexes of entries in a pre-allocated
 * memory pool.
 *
 * The IDs are initially placed on the stack from left-to-right,
 * with the top of stack initially being the leftmost element:
 *
 *   [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
 *    ^--- top of stack
 */

int
qid_init(struct qid *qid, uint32_t len, const char *name, int socket)
{
	uint32_t i;

	qid->ids = rte_malloc_socket(name, len * sizeof(*qid->ids), 0, socket);
	if (qid->ids == NULL) {
		G_LOG(ERR, "%s(%s): insufficient memory to create QID\n",
			__func__, name);
		return -ENOMEM;
	}

	for (i = 0; i < len; i++)
		qid->ids[i] = i;

	qid->len = len;
	qid->top = 0;

	return 0;
}

void
qid_free(struct qid *qid)
{
	rte_free(qid->ids);
	qid->ids = NULL;
}

int
qid_push(struct qid *qid, uint32_t id)
{
	if (unlikely(qid->top == 0))
		return -ENOSPC;
	if (unlikely(id >= qid->len))
		return -EINVAL;
	qid->ids[--qid->top] = id;
	return 0;
}

int
qid_pop(struct qid *qid, uint32_t *p_id)
{
	if (unlikely(qid->top >= qid->len))
		return -ENOENT;
	if (unlikely(p_id == NULL))
		return -EINVAL;
	*p_id = qid->ids[qid->top++];
	return 0;
}
