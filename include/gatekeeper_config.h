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
#include <sys/time.h>

#include "gatekeeper_gk.h"
#include "gatekeeper_gt.h"

#ifndef _GATEKEEPER_CONFIG_H_
#define _GATEKEEPER_CONFIG_H_

/* 
 * XXX #14 Sample parameters for test only.
 * They should be configured in the configuration step.
 */
#define GATEKEEPER_MAX_PORTS	(4)
#define GATEKEEPER_MAX_QUEUES	(8)

/*
 * XXX #14 Sample parameters for test only.
 * They should be analyzed or tested further to find optimal values.
 *
 * Larger queue size can mitigate bursty behavior, but can also increase 
 * pressure on cache and lead to lower performance.
 */
#define GATEKEEPER_NUM_RX_DESC	(128)
#define GATEKEEPER_NUM_TX_DESC	(512)

/* 
 * XXX #14 Sample parameter for the number of elements in the mbuf pool.
 * This should be analyzed or tested further to find optimal value.
 *
 * The optimum size (in terms of memory usage) for a mempool is when it is a 
 * power of two minus one.
 *
 * Need to provision enough memory for the worst case,
 * since each queue needs at least
 * GATEKEEPER_NUM_RX_DESC + GATEKEEPER_NUM_TX_DESC + max_pkt_burst
 * descriptors. i.e., GATEKEEPER_DESC_PER_QUEUE =
 * (GATEKEEPER_NUM_RX_DESC + GATEKEEPER_NUM_TX_DESC \
 *		+ max_pkt_burst (let's say 32)) = 672.
 *
 * So, the pool size should be at least the maximum number of queues * 
 *		number of descriptors per queue, i.e., 
 * (GATEKEEPER_MAX_PORTS * GATEKEEPER_MAX_QUEUES * \
 *              GATEKEEPER_DESC_PER_QUEUE - 1) = 5376.
 */
#define GATEKEEPER_MBUF_SIZE (8191)

/* 
 * XXX #14 Sample parameter for the size of the per-core object cache,
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

extern const uint16_t LUA_MSG_MAX_LEN;

/* Configuration for the Dynamic Config functional block. */
struct dynamic_config {

	/* The lcore id that the block is running on. */
	unsigned int     lcore_id;

	/* Reference to the gk configuration struct. */
	struct gk_config *gk;

	/* Reference to the gt configuration struct. */
	struct gt_config *gt;

	/* Log level for Dynamic Configuration block. */
	uint32_t         log_level;
	/* Dynamic logging type, assigned at runtime. */
	int              log_type;
	/* Log ratelimit interval in ms for Dynamic Configuration block. */
	uint32_t         log_ratelimit_interval_ms;
	/* Log ratelimit burst size for Dynamic Configuration block. */
	uint32_t         log_ratelimit_burst;

	/*
	 * The fields below are for internal use.
	 * Configuration files should not refer to them.
	 */

	/* The server socket descriptor. */
	int              sock_fd;

	/* The file path that the Unix socket will use. */
	char             *server_path;

	/* Specify the receiving timeouts until reporting an error. */
	struct timeval   rcv_time_out;

	/* The directory for Lua files of dynamic configuration. */
	char             *lua_dy_base_dir;

	/* The Lua file for initializing dynamic configuration. */
	char             *dynamic_config_file;
};

int config_gatekeeper(const char *lua_base_dir,
	const char *gatekeeper_config_file);
int set_lua_path(lua_State *l, const char *path);
struct dynamic_config *get_dy_conf(void);
void set_dyc_timeout(unsigned sec, unsigned usec,
	struct dynamic_config *dy_conf);
int run_dynamic_config(struct gk_config *gk_conf, struct gt_config *gt_conf,
	const char *server_path, const char *lua_dy_base_dir,
	const char *dynamic_config_file, struct dynamic_config *dy_conf);

#endif /* _GATEKEEPER_CONFIG_H_ */
