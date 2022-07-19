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

#include <string.h>
#include <memblock.h>

struct memblock_head *
memblock_alloc_block(size_t size)
{
	const size_t head_length = memblock_align(sizeof(struct memblock_head));
	struct memblock_head *block;

	/* Avoid wasting bytes that wouldn't be used due to misalignment. */
	size = memblock_align(size);

	block = rte_malloc("memblock", head_length + size, 0);
	if (unlikely(block == NULL))
		return NULL;

	block->next = ((char *)block) + head_length;
	block->end  = block->next + size;
	return block;
}

void
memblock_free_all(struct memblock_head *head)
{
	const size_t head_length = memblock_align(sizeof(struct memblock_head));
	head->next = ((char *)head) + head_length;
}

void *
memblock_alloc(struct memblock_head *head, size_t size)
{
	char *block;
	char *next;

	if (unlikely(size == 0))
		return NULL;
	size = memblock_align(size);

	block = head->next;
	next = block + size;
	if (unlikely(next > head->end))
		return NULL;

	head->next = next;
	return block;
}

void *
memblock_calloc(struct memblock_head *head, size_t num, size_t size)
{
	size_t tot_size = num * size;
	void *ret = memblock_alloc(head, tot_size);

	if (unlikely(ret == NULL))
		return NULL;

	return memset(ret, 0, tot_size);
}
