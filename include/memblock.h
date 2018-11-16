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

#ifndef MEMBLOCK_H
#define MEMBLOCK_H

#include <rte_common.h>
#include <rte_branch_prediction.h>
#include <rte_malloc.h>

#include <stddef.h>

struct memblock_head {
	char		*next;
	char const	*end;
};

static inline size_t
memblock_align(size_t size)
{
	const size_t alignment = RTE_MAX(sizeof(double), sizeof(void *));
	const size_t mask = alignment - 1;

	RTE_BUILD_BUG_ON(!RTE_IS_POWER_OF_2(alignment));

	return unlikely(size & mask) ? (size & ~mask) + alignment : size;
}

#define MEMBLOCK_DEF_INIT(name, size)				\
	struct {						\
		struct memblock_head	head;			\
		char			block[size];		\
	} name = {						\
		.head.next = name.block,			\
		.head.end  = name.block + memblock_align(size)	\
	}

#define memblock_salloc(memblock, size)		\
	memblock_alloc(&memblock.head, size)

#define memblock_scalloc(memblock, num, size)	\
	memblock_calloc(&memblock.head, num, size)

#define memblock_sfree_all(memblock)		\
	do {					\
		type(memblock) *b = &memblock;	\
		b->head.next = b->block;	\
	} while (0)

struct memblock_head *memblock_alloc_block(size_t size);

static inline void memblock_free_block(struct memblock_head *head)
{
	rte_free(head);
}

void *memblock_alloc(struct memblock_head *head, size_t size);
void *memblock_calloc(struct memblock_head *head, size_t num, size_t size);

void memblock_free_all(struct memblock_head *head);

#endif /* MEMBLOCK_H */
