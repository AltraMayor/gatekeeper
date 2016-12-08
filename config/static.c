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

#include <stdio.h>
#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>

#include <rte_lcore.h>
#include <rte_log.h>
#include <rte_debug.h>

#include "gatekeeper_config.h"
#include "gatekeeper_main.h"

/* TODO Get the install-path via Makefile. */
#define LUA_BASE_DIR               "./lua"
#define GATEKEEPER_CONFIG_FILE     "gatekeeper_config.lua"

/*
 * Return a table with all lcore ids but the lcore id of the master lcore.
 * Function to be called from Lua.
 */
static int
l_list_lcores(lua_State *l)
{
	unsigned int i;
	lua_Integer lua_index = 1;

	lua_newtable(l);	/* Result. */

	/* Only list slave lcores because the master lcore is special. */
	RTE_LCORE_FOREACH_SLAVE(i) {
		/* Push lcore id into Lua stack. */
		lua_pushinteger(l, i);
		/* Add lcore id to the table at @lua_index position. */
		lua_rawseti(l, -2, lua_index++);
	}

	return 1;	/* Return the table. */
}

static int
l_rte_lcore_to_socket_id(lua_State *l)
{
	/* First (and only argument) must be the lcore id. */
	lua_Integer lcore_id = luaL_checkinteger(l, 1);
	if (lcore_id < 0 || lcore_id >= RTE_MAX_LCORE)
		luaL_error(l, "The first argument of rte_lcore_to_socket_id() must be between %i and %i, inclusive\n",
			0, RTE_MAX_LCORE - 1);
	lua_pushinteger(l, rte_lcore_to_socket_id(lcore_id));
	return 1;
}

static const struct luaL_reg gatekeeper [] = {
	{"list_lcores",			l_list_lcores},
	{"rte_lcore_to_socket_id",	l_rte_lcore_to_socket_id},
	{NULL,				NULL}	/* Sentinel. */
};

static int
set_lua_path(lua_State *l, const char *path)
{
	int ret;
	char new_path[1024];

	lua_getglobal(l, "package");
	lua_getfield(l, -1, "path");

	ret = snprintf(new_path, sizeof(new_path), "%s;%s/?.lua", lua_tostring(l, -1), path);
	RTE_ASSERT(ret < sizeof(new_path));

	lua_pop(l, 1);
	lua_pushstring(l, new_path);
	lua_setfield(l, -2, "path");
	lua_pop(l, 1);

	return ret;
}

int
config_and_launch(void)
{
	int ret;
	char lua_entry_path[128];
	lua_State *lua_state;


	ret = snprintf(lua_entry_path, sizeof(lua_entry_path), \
			"%s/%s", LUA_BASE_DIR, GATEKEEPER_CONFIG_FILE);
	RTE_ASSERT(ret < sizeof(lua_entry_path));

	lua_state = luaL_newstate();
	if (!lua_state) {
		RTE_LOG(ERR, GATEKEEPER,
			"config: failed to create new Lua state!\n");
		return -1;
	}

	luaL_openlibs(lua_state);
	luaL_register(lua_state, "gatekeeper", gatekeeper);
	set_lua_path(lua_state, LUA_BASE_DIR);
	ret = luaL_loadfile(lua_state, lua_entry_path);
	if (ret != 0) {
		RTE_LOG(ERR, GATEKEEPER,
			"config: %s!\n", lua_tostring(lua_state, -1));
		ret = -1;
		goto out;
	}

	/*
	 * Calls a function in protected mode.
	 * int lua_pcall (lua_State *L, int nargs, int nresults, int errfunc);
	 * @nargs: the number of arguments that you pushed onto the stack.
	 * @nresults: the number of results that the funtion will push onto
	 * the stack.
	 * @errfunc: if "0", it represents the error message returned on
	 * the stack is exactly the original error message.
	 * Otherwise, it presents the index of the error handling function.
	 */
	ret = lua_pcall(lua_state, 0, 0, 0);
	if (ret != 0) {
		RTE_LOG(ERR, GATEKEEPER,
			"config: %s!\n", lua_tostring(lua_state, -1));
		ret = -1;
		goto out;
	}

	/* Function to be called. */
	lua_getglobal(lua_state, "gatekeeper_init");
	ret = lua_pcall(lua_state, 0, 1, 0);
	if (ret != 0) {
		RTE_LOG(ERR, GATEKEEPER,
			"config: %s!\n", lua_tostring(lua_state, -1));
		ret = -1;
		goto out;
	}

	ret = luaL_checkinteger(lua_state, -1);
	if (ret < 0)
		RTE_LOG(ERR, GATEKEEPER,
			"config: gatekeeper_init() return value is %d!\n",
			ret);

out:
	lua_close(lua_state);
	return ret;
}
