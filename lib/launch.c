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

#include <stdbool.h>
#include <string.h>

#include <rte_malloc.h>
#include <rte_lcore.h>
#include <rte_debug.h>
#include <rte_log.h>

#include "gatekeeper_launch.h"
#include "list.h"
#include "gatekeeper_main.h"

static struct launch_heads {
	struct list_head stage1;
	struct list_head stage2;
	struct list_head stage3;
} launch_heads = {
	.stage1 = LIST_HEAD_INIT(launch_heads.stage1),
	.stage2 = LIST_HEAD_INIT(launch_heads.stage2),
	.stage3 = LIST_HEAD_INIT(launch_heads.stage3),
};

struct stage1_entry {
	struct list_head list;
	lcore_function_t *f;
	void             *arg;
};

int
launch_at_stage1(lcore_function_t *f, void *arg)
{
	struct stage1_entry *entry;

	entry = rte_malloc(__func__, sizeof(*entry), 0);
	if (entry == NULL) {
		G_LOG(ERR, "launch: %s: DPDK ran out of memory", __func__);
		return -1;
	}

	entry->f = f;
	entry->arg = arg;
	list_add_tail(&entry->list, &launch_heads.stage1);
	return 0;
}

static int
launch_stage1(void)
{
	struct stage1_entry *entry, *next;

	list_for_each_entry_safe(entry, next, &launch_heads.stage1, list) {
		int ret = entry->f(entry->arg);
		if (ret != 0)
			return ret;
		list_del(&entry->list);
		rte_free(entry);
	}

	return 0;
}

void
pop_n_at_stage1(int n)
{
	while (n > 0 && !list_empty(&launch_heads.stage1)) {
		struct stage1_entry *last =
			list_last_entry(&launch_heads.stage1,
			struct stage1_entry, list);
		list_del(&last->list);
		rte_free(last);
		n--;
	}
}

struct stage2_entry {
	struct list_head list;
	lcore_function_t *f;
	void             *arg;
};

int
launch_at_stage2(lcore_function_t *f, void *arg)
{
	struct stage2_entry *entry;

	entry = rte_malloc(__func__, sizeof(*entry), 0);
	if (entry == NULL) {
		G_LOG(ERR, "launch: %s: DPDK ran out of memory", __func__);
		return -1;
	}

	entry->f = f;
	entry->arg = arg;
	list_add_tail(&entry->list, &launch_heads.stage2);
	return 0;
}

static int
launch_stage2(void)
{
	struct stage2_entry *entry, *next;

	list_for_each_entry_safe(entry, next, &launch_heads.stage2, list) {
		int ret = entry->f(entry->arg);
		if (ret != 0)
			return ret;
		list_del(&entry->list);
		rte_free(entry);
	}

	return 0;
}

void
pop_n_at_stage2(int n)
{
	while (n > 0 && !list_empty(&launch_heads.stage2)) {
		struct stage2_entry *last =
			list_last_entry(&launch_heads.stage2,
			struct stage2_entry, list);
		list_del(&last->list);
		rte_free(last);
		n--;
	}
}

struct stage3_entry {
	struct list_head list;
	char             *name;
	lcore_function_t *f;
	void             *arg;
	unsigned int     lcore_id;
};

int
launch_at_stage3(const char *name, lcore_function_t *f, void *arg,
	unsigned int lcore_id)
{
	struct stage3_entry *entry;
	char *name_cpy;

	name_cpy = rte_strdup(__func__, name);
	if (name_cpy == NULL)
		goto fail;

	entry = rte_malloc(__func__, sizeof(*entry), 0);
	if (entry == NULL) {
		G_LOG(ERR, "launch: %s: DPDK ran out of memory", __func__);
		goto name_cpy;
	}

	entry->name = name_cpy;
	entry->f = f;
	entry->arg = arg;
	entry->lcore_id = lcore_id;

	list_add_tail(&entry->list, &launch_heads.stage3);
	return 0;

name_cpy:
	rte_free(name_cpy);
fail:
	return -1;
}

static inline void
free_stage3_entry(struct stage3_entry *entry)
{
	rte_free(entry->name);
	rte_free(entry);
}

static int
launch_stage3(void)
{
	unsigned int master_id = rte_get_master_lcore();
	struct stage3_entry *entry, *next;

	RTE_VERIFY(master_id == rte_lcore_id());

	list_for_each_entry_safe(entry, next, &launch_heads.stage3, list) {
		int ret;

		if (entry->lcore_id == master_id) {
			/*
			 * Postpone the execution of this call since
			 * this thread is running on the master lcore.
			 */
			continue;
		}

		ret = rte_eal_remote_launch(entry->f, entry->arg,
			entry->lcore_id);
		if (ret != 0) {
			G_LOG(ERR, "launch: lcore %u failed to launch %s\n",
				entry->lcore_id, entry->name);
			return ret;
		}
		list_del(&entry->list);
		free_stage3_entry(entry);
	}

	return 0;
}

static int
run_master_if_applicable(void)
{
	unsigned int master_id = rte_get_master_lcore();
	struct stage3_entry *first;
	int ret;

	RTE_VERIFY(master_id == rte_lcore_id());

	if (list_empty(&launch_heads.stage3))
		return 0;

	if (!list_is_singular(&launch_heads.stage3)) {
		G_LOG(ERR, "launch: list of stage 3 functions should not contain multiple master lcore entries\n");
		return -1;
	}

	first = list_first_entry(&launch_heads.stage3, struct stage3_entry,
		list);
	if (first->lcore_id != master_id) {
		G_LOG(ERR, "launch: list of stage 3 functions should not contain non-master lcore entries in %s\n",
			__func__);
		return -1;
	}

	list_del(&first->list);
	ret = first->f(first->arg);
	free_stage3_entry(first);
	return ret;
}

void
pop_n_at_stage3(int n)
{
	while (n > 0 && !list_empty(&launch_heads.stage3)) {
		struct stage3_entry *last =
			list_last_entry(&launch_heads.stage3,
			struct stage3_entry, list);
		list_del(&last->list);
		free_stage3_entry(last);
		n--;
	}
}

int
launch_gatekeeper(void)
{
	int ret;

	ret = launch_stage1();
	if (ret != 0)
		return -1;

	ret = launch_stage2();
	if (ret != 0)
		return -1;

	ret = launch_stage3();
	if (ret != 0)
		return -1;

	return run_master_if_applicable();
}
