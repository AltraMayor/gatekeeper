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

#ifndef _GATEKEEPER_SOL_H_
#define _GATEKEEPER_SOL_H_

#include <rte_approx.h>
#include <rte_cycles.h>
#include <rte_reciprocal.h>

#include "list.h"

struct priority_req {
	/* Doubly-linked list node. */
	struct list_head    list;
	/* The packet for this request. */
	struct rte_mbuf     *pkt;
	/* The priority of this request. */
	uint8_t             priority;
};

/*
 * The maximum priority that a packet can be assigned.
 *
 * Packets are assigned priorities [0, 63] due to
 * the limits of the IP DSCP field.
 */
#define GK_MAX_REQ_PRIORITY (63)

/*
 * XXX The DPDK packet scheduler uses __rte_cache_aligned
 * on member @memory and on the struct as a whole. Should
 * it be used here?
 */
struct req_queue {
	/* Length of the priority queue. */
	uint32_t              len;
	/* The highest priority of any packet currently in the queue. */
	uint16_t              highest_priority;
	/* The lowest priority of any packet currently in the queue. */
	uint16_t              lowest_priority;

	/*
	 * The head of the priority queue, referencing the node
	 * that contains the packet with the highest priority.
	 */
	struct list_head      head;
	/* Array of pointers to packets of each priority. */
	struct priority_req   *priorities[GK_MAX_REQ_PRIORITY + 1];

	/*
	 * Token bucket algorithm state.
	 */

	/* Capacity of the token bucket (the max number of credits). */
	uint64_t              tb_max_credit_bytes;

	/* Number of credits currently in the token bucket. */
	uint64_t              tb_credit_bytes;

	/*
	 * CPU cycles per byte for the request queue,
	 * approximated as a rational a/b.
	 */
	uint64_t              cycles_per_byte_a;
	uint64_t              cycles_per_byte_b;

	/*
	 * The floor function of CPU cycles per byte, which is useful
	 * to quickly determine whether we have enough cycles to
	 * add some number of credits before executing a division.
	 */
	uint64_t              cycles_per_byte_floor;

	/* Current CPU time measured in CPU cyles. */
	uint64_t              time_cpu_cycles;
};

/* Configuration for the Solicitor functional block. */
struct sol_config {
	unsigned int       lcore_id;

	/* Maximum number of requests to store in priority queue at once. */
	unsigned int       pri_req_max_len;

	/*
	 * Bandwidth limit for the priority queue of requests,
	 * as a percentage of the capacity of the link. Must
	 * be > 0 and < 1.
	 */
	double             req_bw_rate;

	/* Maximum request enqueue/dequeue size. */
	unsigned int       enq_burst_size;
	unsigned int       deq_burst_size;

	/* Parameters to setup the mailbox instance. */
	unsigned int       mailbox_mem_cache_size;

	/*
	 * The fields below are for internal use.
	 * Configuration files should not refer to them.
	 */

	/* Priority queue for request packets. */
	struct req_queue   req_queue;

	/*
	 * Mailbox into which GK instances enqueue request packets
	 * to be serviced and sent out by the Solicitor.
	 */
	struct mailbox     mb;

	/* TX queue on the back interface. */
	uint16_t           tx_queue_back;
	struct net_config  *net;
};

struct sol_config *alloc_sol_conf(void);
int run_sol(struct net_config *net_conf, struct sol_config *sol_conf);
int gk_solicitor_enqueue(struct sol_config *sol_conf, struct rte_mbuf *pkt,
	uint8_t priority);

#endif /* _GATEKEEPER_SOL_H_ */
