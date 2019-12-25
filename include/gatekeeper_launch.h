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

#ifndef _GATEKEEPER_LAUNCH_H_
#define _GATEKEEPER_LAUNCH_H_

#include <rte_launch.h>

/*
 * Postpone the execution of f(arg) until the Lua configuration finishes,
 * but before the network devices start.
 *
 * If f() returns a non-zero, the inilization terminates in error.
 *
 * ATTENTION:
 * This initilization stage is perfect for allocation of queues in
 * the network devices. HOWEVER, if you're going to allocate any queue,
 * DO NOT call this function, but net_launch_at_stage1() instead!
 *
 * RETURN
 *	Return 0 if success; otherwise -1.
 */
int
launch_at_stage1(lcore_function_t *f, void *arg);

/* Drop the @n last entries of stage1. */
void
pop_n_at_stage1(int n);

/*
 * Once stage 1 finishes, the network devices are started, and
 * stage 2 begins.
 *
 * According to the DPDK documentation, any functions from rte_ethdev.h
 * must be called after the network devices are started, which includes
 * filters functions in general.
 * Therefore, this initilization stage is perfect for registering filters in
 * the network devices.
 *
 * RETURN
 *	Return 0 if success; otherwise -1.
 */
int
launch_at_stage2(lcore_function_t *f, void *arg);

/* Drop the @n last entries of stage2. */
void
pop_n_at_stage2(int n);

/*
 * Once stage 2 finishes, stage 3 begins.
 *
 * This initilization stage runs f(arg) on lcore_id.
 *
 * RETURN
 *	Return 0 if success; otherwise -1.
 */
int
launch_at_stage3(const char *name, lcore_function_t *f, void *arg,
	unsigned int lcore_id);

/* Drop the @n last entries of stage3. */
void
pop_n_at_stage3(int n);

int
launch_gatekeeper(void);

#endif /* _GATEKEEPER_LAUNCH_H_ */
