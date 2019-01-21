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
