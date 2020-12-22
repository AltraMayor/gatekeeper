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

#include <stdint.h>

#include <rte_atomic.h>

#include "list.h"

/*
 * The maximum priority that a packet can be assigned.
 *
 * Packets are assigned priorities [0, 63] due to
 * the limits of the IP DSCP field.
 */
#define GK_MAX_REQ_PRIORITY (63)

/*
 * XXX #36 The DPDK packet scheduler uses __rte_cache_aligned
 * on member @memory and on the struct as a whole. Should
 * it be used here?
 */
struct req_queue {
	/* Length of the priority queue. */
	uint32_t         len;
	/* The highest priority of any packet currently in the queue. */
	uint16_t         highest_priority;
	/* The lowest priority of any packet currently in the queue. */
	uint16_t         lowest_priority;

	/*
	 * The head of the priority queue, referencing the node
	 * that contains the packet with the highest priority.
	 */
	struct list_head head;
	/* Array of pointers to the last packets of each priority. */
	struct rte_mbuf  *priorities[GK_MAX_REQ_PRIORITY + 1];

	/*
	 * Token bucket algorithm state.
	 */

	/* Capacity of the token bucket (the max number of credits). */
	uint64_t         tb_max_credit_bytes;

	/* Number of credits currently in the token bucket. */
	uint64_t         tb_credit_bytes;

	/*
	 * CPU cycles per byte for the request queue,
	 * approximated as a rational a/b.
	 */
	uint64_t         cycles_per_byte_a;
	uint64_t         cycles_per_byte_b;

	/*
	 * The floor function of CPU cycles per byte, which is useful
	 * to quickly determine whether we have enough cycles to
	 * add some number of credits before executing a division.
	 */
	uint64_t         cycles_per_byte_floor;

	/* Current CPU time measured in CPU cyles. */
	uint64_t         time_cpu_cycles;
};

/* Structures for each SOL instance. */
struct sol_instance {
	/*
	 * Ring into which GK instances enqueue request packets
	 * to be serviced and sent out by the Solicitor.
	 */
	struct rte_ring  *ring;

	/* TX queue on the back interface. */
	uint16_t         tx_queue_back;

	/* Priority queue for request packets. */
	struct req_queue req_queue;
} __rte_cache_aligned;

/* Configuration for the Solicitor functional block. */
struct sol_config {
	/* Maximum number of requests to store in priority queue at once. */
	unsigned int        pri_req_max_len;

	/*
	 * Bandwidth limit for the priority queue of requests,
	 * as a percentage of the capacity of the link. Must
	 * be > 0 and < 1.
	 */
	double              req_bw_rate;

	/* Maximum request enqueue/dequeue size. */
	unsigned int        enq_burst_size;
	unsigned int        deq_burst_size;

	/* Token bucket rate approximation error. */
	double              tb_rate_approx_err;

	/*
	 * Bandwidth of request channel in Mbps.
	 *
	 * Used only in the case when the Solicitor
	 * block cannot read the back interface's
	 * available bandwidth, such as is the case
	 * with the Amazon ENA. Should be calculated
	 * by the operator.
	 *
	 * Should be set to 0 if not needed.
	 */
	double              req_channel_bw_mbps;

	/* Log level for SOL block. */
	uint32_t            log_level;
	/* Dynamic logging type, assigned at runtime. */
	int                 log_type;
	/* Log ratelimit interval in ms for SOL block. */
	uint32_t            log_ratelimit_interval_ms;
	/* Log ratelimit burst size for SOL block. */
	uint32_t            log_ratelimit_burst;

	/*
	 * The fields below are for internal use.
	 * Configuration files should not refer to them.
	 */

	/*
	 * Number of references to this struct.
	 *
	 * The resources associated to this struct are only freed
	 * when field @ref_cnt reaches zero.
	 *
	 * Use sol_conf_hold() and sol_conf_put() to acquire and release
	 * a reference to this struct.
	 */
	rte_atomic32_t      ref_cnt;

	/* The lcore ids at which each instance runs. */
	unsigned int        *lcores;

	/* The number of lcore ids in @lcores. */
	int                 num_lcores;

	struct sol_instance *instances;
	struct net_config   *net;
};

struct sol_config *alloc_sol_conf(void);
int run_sol(struct net_config *net_conf, struct sol_config *sol_conf);
int gk_solicitor_enqueue_bulk(struct sol_instance *instance,
	struct rte_mbuf **pkts, uint16_t num_pkts);

static inline void
sol_conf_hold(struct sol_config *sol_conf)
{
	rte_atomic32_inc(&sol_conf->ref_cnt);
}

int sol_conf_put(struct sol_config *sol_conf);

#endif /* _GATEKEEPER_SOL_H_ */
