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

#ifndef _GATEKEEPER_GK_CO_H_
#define _GATEKEEPER_GK_CO_H_

#include <stdbool.h>
#include <string.h>
#include <coro.h>
#include <list.h>

#include "gatekeeper_gk.h"
#include "gatekeeper_acl.h"

struct gk_co {
	/*
	 * Attach this coroutine to work->working_cos while
	 * this coroutine is working.
	 */
	struct list_head    co_list;
	/* structs from libcoro. */
	struct coro_stack   stack;
	struct coro_context coro;
	/* Task assigned to this coroutine. */
	struct list_head    task_queue;
	struct gk_co_work   *work;
};

struct gk_co_task *task;

typedef void (*gk_co_task_func_t)(struct gk_co *this_co,
	struct gk_co_task *task);

struct gk_co_task {
	/*
	 * Once the task is assigned to a coroutine,
	 * attach this task to co->task_queue.
	 */
	struct list_head  task_list;
	/*
	 * @task_hash is used to assign the task to a coroutine.
	 *
	 * This is important to avoid race conditions between coroutines.
	 * For example, assume that two tasks that are going to work on
	 * the same flow entry are assigned to two different coroutines, and
	 * that the corresponding flow entry is not available in
	 * the flow table, both coroutines may try to add the same flow entry.
	 * If these two tasks share the same task hash, both tasks are going to
	 * be assigned to the same coroutine.
	 */
	uint32_t          task_hash;
	void              *task_arg;
	gk_co_task_func_t task_func;
};

struct gk_co_work {
	/* The coroutines working on the tasks. */
	struct list_head working_cos;
	/* Coroutines available to do the work. */
	struct gk_co     *cos;
	/* Number of coroutines available for the next batch of work. */
	uint16_t         co_num;
	/* Total number of coroutines available at field @cos. */
	uint16_t         co_max_num;
	/* Index of the next coroutine to use when a task has no task hash. */
	uint16_t         any_co_index;
	/* How field @co_num will change for the next batch of work. */
	int16_t          co_delta_num;
	/*
	 * Previous value of field @co_num.
	 * When the value of this field is zero, an invalid value for @co_num,
	 * the value of field @avg_cycles_per_task is not meaningful.
	 */
	uint16_t         co_prv_num;
	/*
	 * Average number of cycles per task when @co_num was equal to
	 * @co_prv_num.
	 */
	double           avg_cycles_per_task;

	struct gk_config   *gk_conf;
	struct gk_instance *instance;

	/* All preallocated tasks available to do work. */
	struct gk_co_task *all_tasks;
	/* The total number of taks available at field @all_tasks. */
	const uint32_t task_total;
	/* Current number of tasks used at field @all_tasks. */
	uint32_t task_num;

	/* Fields for front packets and mailbox messages. */
	/*
	 * This is a single-entry-per-bucket hash table.
	 * This flow entries are reused between tasks assigned to
	 * the same coroutine.
	 */
	struct flow_entry ** const leftover;
	/*
	 * Flow entries that has not been inserted in the flow table, but
	 * they may be present in @leftover.
	 */
	struct flow_entry * const temp_fes;
	/* Number of entries in used in @temp_fes. */
	uint16_t temp_fes_num;
	/*
	 * Mask for the hash table @leftover.
	 * It must be of the form (2^n - 1) for any n >= 0.
	 */
	const uint32_t leftover_mask;

	/* Fields for front and back packets. */
	uint16_t tx_front_num_pkts;
	uint16_t tx_back_num_pkts;
	struct rte_mbuf ** const tx_front_pkts;
	struct rte_mbuf ** const tx_back_pkts;
	/*
	 * The following field is only needed when the RSS hash is not
	 * available.
	 */
	struct ipacket * const packets;

	/* Fields for the front packets only. */
	uint16_t          front_num_req;
	uint16_t          front_num_arp;
	struct rte_mbuf   ** const front_req_bufs;
	struct rte_mbuf   ** const front_arp_bufs;
	struct acl_search front_acl4;
	struct acl_search front_acl6;
	bool front_ipv4_configured;
	bool front_ipv6_configured;

	/* Fields for the front packets only. */
	uint16_t          back_num_arp;
	struct rte_mbuf   ** const back_arp_bufs;
	struct acl_search back_acl4;
	struct acl_search back_acl6;
};

/* Declare and initialize a struct gk_co_work. */
#define DEFINE_GK_CO_WORK(name, max_front_pkts, max_back_pkts,		\
		max_mailbox, lo_mask, task_extra)			\
	struct gk_co_task name##_all_tasks_array[(max_front_pkts) +	\
		(max_back_pkts) + (max_mailbox) + (task_extra)];	\
	struct flow_entry *name##_leftover_array[(lo_mask) + 1];	\
	struct flow_entry name##_temp_fes_array[			\
		(max_front_pkts) + (max_mailbox)];			\
	struct rte_mbuf *name##_tx_front_pkts_array[			\
		(max_front_pkts) + (max_back_pkts)];			\
	struct rte_mbuf *name##_tx_back_pkts_array[			\
		(max_front_pkts) + (max_back_pkts)];			\
	struct ipacket name##_packets_array[				\
		(max_front_pkts) + (max_back_pkts)];			\
	struct rte_mbuf *name##_front_req_bufs_array[(max_front_pkts)];	\
	struct rte_mbuf *name##_front_arp_bufs_array[(max_front_pkts)];	\
	DECLARE_ACL_SEARCH_VARIABLE_PART(front_acl4, (max_front_pkts));	\
	DECLARE_ACL_SEARCH_VARIABLE_PART(front_acl6, (max_front_pkts));	\
	struct rte_mbuf *name##_back_arp_bufs_array[(max_back_pkts)];	\
	DECLARE_ACL_SEARCH_VARIABLE_PART(back_acl4, (max_back_pkts));	\
	DECLARE_ACL_SEARCH_VARIABLE_PART(back_acl6, (max_back_pkts));	\
	struct gk_co_work name = {					\
		.working_cos = LIST_HEAD_INIT(name.working_cos),	\
		.cos = NULL,						\
		.co_num = 0,						\
		.co_max_num = 0,					\
		.any_co_index = 0,					\
		.co_delta_num = 1,					\
		.co_prv_num = 0,					\
		.avg_cycles_per_task = 0,				\
		.gk_conf = NULL,					\
		.instance = NULL,					\
		.all_tasks = name##_all_tasks_array,			\
		.task_total = (max_front_pkts) + (max_back_pkts) +	\
			(max_mailbox) + (task_extra),			\
		.task_num = 0,						\
		.leftover = memset(name##_leftover_array, 0,		\
			sizeof(name##_leftover_array)),			\
		.temp_fes = name##_temp_fes_array,			\
		.temp_fes_num = 0,					\
		.leftover_mask = (lo_mask),				\
		.tx_front_num_pkts = 0,					\
		.tx_back_num_pkts  = 0,					\
		.tx_front_pkts = name##_tx_front_pkts_array,		\
		.tx_back_pkts  = name##_tx_back_pkts_array,		\
		.packets = name##_packets_array,			\
		.front_num_req = 0,					\
		.front_num_arp = 0,					\
		.front_req_bufs = name##_front_req_bufs_array,		\
		.front_arp_bufs = name##_front_arp_bufs_array,		\
		.front_acl4 = ACL_SEARCH_INIT(front_acl4),		\
		.front_acl6 = ACL_SEARCH_INIT(front_acl6),		\
		.front_ipv4_configured = false,				\
		.front_ipv6_configured = false,				\
		.back_num_arp = 0,					\
		.back_arp_bufs = name##_back_arp_bufs_array,		\
		.back_acl4 = ACL_SEARCH_INIT(back_acl4),		\
		.back_acl6 = ACL_SEARCH_INIT(back_acl6),		\
	}

static inline struct gk_co *
get_task_owner_co(struct gk_co_work *work, struct gk_co_task *task)
{
	return &work->cos[task->task_hash % work->co_num];
}

static inline void
__schedule_task(struct gk_co *task_owner_co, struct gk_co_task *task)
{
	list_add_tail(&task->task_list, &task_owner_co->task_queue);
}

static inline void
schedule_task(struct gk_co_work *work, struct gk_co_task *task)
{
	__schedule_task(get_task_owner_co(work, task), task);
}

/* Uniformly distribuite tasks with no task hash among coroutines. */
static inline void
schedule_task_to_any_co(struct gk_co_work *work, struct gk_co_task *task)
{
	__schedule_task(&work->cos[work->any_co_index], task);
	work->any_co_index = (work->any_co_index + 1) % work->co_num;
}

void
gk_co_main(void *arg);

#endif /* _GATEKEEPER_GK_CO_H_ */
