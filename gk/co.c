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

#include "co.h"

static struct gk_co *
get_next_co(struct gk_co *this_co)
{
	/*
	 * It is unlikely because as long as there is more than
	 * one working coroutine, there is at least 50% chance that
	 * @this_co is not the last working coroutine.
	 */
	if (unlikely(this_co->co_list.next == &this_co->work->working_cos)) {
		/* @this_co is the last working co. */
		return list_first_entry(&this_co->work->working_cos,
			struct gk_co, co_list);
	}
	return list_next_entry(this_co, co_list);
}

static struct gk_co_task *
next_task(struct gk_co *this_co)
{
	while (true) {
		struct gk_co *next_co;

		/*
		 * This test is likely because if @this_co has at least
		 * one task, there's at least 50% that it will be true because
		 * this function is called twice.
		 */
		if (likely(!list_empty(&this_co->task_queue))) {
			/*
			 * @this_co has assigned tasks.
			 * Return the first assigned task.
			 */
			struct gk_co_task *task = list_first_entry(
				&this_co->task_queue, struct gk_co_task,
				task_list);
			list_del(&task->task_list);
			return task;
		}

		/* There is no more tasks assigned to @this_co. */

		next_co = get_next_co(this_co);

		/* Make @this_co idle. */
		list_del(&this_co->co_list);

		/* Transfer control to another coroutine. */
		if (likely(this_co != next_co)) {
			/*
			 * @this_co is NOT the last working coroutine.
			 * Yield to the next coroutine.
			 */
			coro_transfer(&this_co->coro, &next_co->coro);
		} else {
			/*
			 * No more work and no more working coroutines;
			 * @this_co is the last working coroutine.
			 * Return to the main coroutine.
			 */
			coro_transfer(&this_co->coro,
				&this_co->work->instance->coro_root);
		}
	}
}

void
gk_co_main(void *arg)
{
	struct gk_co *this_co = arg;
	struct gk_co_task *task = next_task(this_co);

	while (likely(task != NULL)) {
		task->task_func(this_co, task);
		task = next_task(this_co);
	}

	rte_panic("%s() terminated\n", __func__);
}
