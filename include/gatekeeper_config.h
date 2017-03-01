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

#include <lua.h>

#ifndef _GATEKEEPER_CONFIG_H_
#define _GATEKEEPER_CONFIG_H_

/* 
 * XXX Sample parameters for test only. 
 * They should be configured in the configuration step.
 */
#define GATEKEEPER_MAX_PORTS	(4)
#define GATEKEEPER_MAX_QUEUES	(8)

/*
 * XXX Sample parameters for test only.
 * They should be analyzed or tested further to find optimal values.
 *
 * Larger queue size can mitigate bursty behavior, but can also increase 
 * pressure on cache and lead to lower performance.
 */
#define GATEKEEPER_NUM_RX_DESC	(128)
#define GATEKEEPER_NUM_TX_DESC	(512)

/* 
 * XXX Sample parameter for the number of elements in the mbuf pool.
 * This should be analyzed or tested further to find optimal value.
 *
 * The optimum size (in terms of memory usage) for a mempool is when it is a 
 * power of two minus one.
 *
 * Need to provision enough memory for the worst case,
 * since each queue needs at least
 * GATEKEEPER_NUM_RX_DESC + GATEKEEPER_NUM_TX_DESC + GATEKEEPER_MAX_PKT_BURST
 * descriptors. i.e., GATEKEEPER_DESC_PER_QUEUE =
 * (GATEKEEPER_NUM_RX_DESC + GATEKEEPER_NUM_TX_DESC \
 *		+ GATEKEEPER_MAX_PKT_BURST (let's say 32)) = 672.
 *
 * So, the pool size should be at least the maximum number of queues * 
 *		number of descriptors per queue, i.e., 
 * (GATEKEEPER_MAX_PORTS * GATEKEEPER_MAX_QUEUES * \
 *              GATEKEEPER_DESC_PER_QUEUE - 1) = 5376.
 */
#define GATEKEEPER_MBUF_SIZE (8191)

/* 
 * XXX Sample parameter for the size of the per-core object cache, 
 * i.e., number of struct rte_mbuf elements in the per-core object cache.
 * this should be analyzed or tested further to find optimal value.
 *
 * Each core deals with at most GATEKEEPER_MAX_PORTS queues, so the cache size
 * should be at least (number of ports * number of descriptors per queue), i.e.,
 * (GATEKEEPER_MAX_PORTS * GATEKEEPER_DESC_PER_QUEUE).
 * 
 * Notice that, this argument must be lower or equal to 
 * CONFIG_RTE_MEMPOOL_CACHE_MAX_SIZE and n / 1.5. 
 * It is advised to choose cache_size to have "n modulo cache_size == 0": 
 * if this is not the case, some elements will always stay in the pool 
 * and will never be used. Here, n is GATEKEEPER_MBUF_SIZE.
 *
 * The maximum cache size can be adjusted in DPDK's .config file: 
 * CONFIG_RTE_MEMPOOL_CACHE_MAX_SIZE.
 */
#define GATEKEEPER_CACHE_SIZE	(512)

#define GATEKEEPER_MAX_PKT_BURST (32)

/* Configuration for the Dynamic Config functional block. */
struct dynamic_config {
	unsigned int	lcore_id;
};

int config_gatekeeper(void);
int set_lua_path(lua_State *l, const char *path);
int run_dynamic_config(const struct dynamic_config *dy_conf);

#endif /* _GATEKEEPER_CONFIG_H_ */
