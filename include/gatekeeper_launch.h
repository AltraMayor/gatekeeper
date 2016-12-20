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

#include "gatekeeper_net.h"

/*
 * Postpone the execution of f(arg) until the Lua configuration finishes,
 * but before the network devices start.
 *
 * This initilization stage is perfect for allocation of queues in
 * the network devices.
 *
 * front_rx_queues, front_tx_queues, back_rx_queues, and back_tx_queues are
 * the number of queues on the front and back interfaces of the receiving and
 * transmitting types. This information must be known while calling
 * lch_launch_at_stage1(), but before f(arg) is called.
 *
 * If the back interface is not enabled, the parameters back_rx_queues and
 * back_tx_queues are ignored.
 *
 * If f() returns a non-zero, the inilization terminates in error.
 *
 * RETURN
 *	Return 0 if success; otherwise -1.
 */
int
launch_at_stage1(struct net_config *net,
	int front_rx_queues, int front_tx_queues,
	int back_rx_queues, int back_tx_queues,
	lcore_function_t *f, void *arg);

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
