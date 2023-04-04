/*
 * Gatekeeper - DDoS protection system.
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
#include <stdbool.h>
#include <lualib.h>
#include <lauxlib.h>

#include <rte_lcore.h>
#include <rte_malloc.h>
#include <rte_log.h>
#include <rte_debug.h>

#include "gatekeeper_config.h"
#include "gatekeeper_main.h"
#include "gatekeeper_gk.h"
#include "gatekeeper_gt.h"

/* Return a table with all lcore ids. Function to be called from Lua. */
static int
l_list_lcores(lua_State *L)
{
	unsigned int i;
	lua_Integer lua_index = 1;

	lua_newtable(L);	/* Result. */

	RTE_LCORE_FOREACH(i) {
		/* Push lcore id into Lua stack. */
		lua_pushinteger(L, i);
		/* Add lcore id to the table at @lua_index position. */
		lua_rawseti(L, -2, lua_index++);
	}

	return 1;	/* Return the table. */
}

static int
l_rte_lcore_to_socket_id(lua_State *L)
{
	/* First (and only argument) must be the lcore id. */
	lua_Integer lcore_id = luaL_checkinteger(L, 1);
	if (lcore_id < 0 || lcore_id >= RTE_MAX_LCORE)
		luaL_error(L, "The first argument of rte_lcore_to_socket_id() must be between %d and %d, inclusive\n",
			0, RTE_MAX_LCORE - 1);
	lua_pushinteger(L, rte_lcore_to_socket_id(lcore_id));
	return 1;
}

static int
protected_gk_assign_lcores(lua_State *L)
{
	uint32_t ctypeid;
	struct gk_config *gk_conf;
	lua_Integer i, n;
	unsigned int *lcores;

	gk_conf = *(struct gk_config **)
		luaL_checkcdata(L, 1, &ctypeid, CTYPE_STRUCT_GK_CONFIG_PTR);
	n = lua_objlen(L, 2);
	lcores = *(unsigned int **)lua_touserdata(L, 3);

	for (i = 1; i <= n; i++) {
		lua_pushinteger(L, i);	/* Push i. */
		lua_gettable(L, 2);	/* Pop i, Push t[i]. */

		/* Check that t[i] is a number. */
		if (!lua_isnumber(L, -1))
			luaL_error(L, "Index %d is not a number", i);
		lcores[i - 1] = lua_tointeger(L, -1);

		lua_pop(L, 1);		/* Pop t[i]. */
	}

	gk_conf->lcores = lcores;
	gk_conf->num_lcores = n;
	return 0; /* No results. */
}

static int
l_gk_assign_lcores(lua_State *L)
{
	uint32_t ctypeid;
	lua_Integer n;
	unsigned int *lcores, **ud;
	uint32_t correct_ctypeid = luaL_get_ctypeid(L,
		CTYPE_STRUCT_GK_CONFIG_PTR);

	/* First argument must be of type CTYPE_STRUCT_GK_CONFIG_PTR. */
	luaL_checkcdata(L, 1, &ctypeid, CTYPE_STRUCT_GK_CONFIG_PTR);
	if (ctypeid != correct_ctypeid)
		luaL_error(L, "Expected `%s' as first argument",
			CTYPE_STRUCT_GK_CONFIG_PTR);

	/* Second argument must be a table. */
	luaL_checktype(L, 2, LUA_TTABLE);

	n = lua_objlen(L, 2); /* Get size of the table. */
	if (n <= 0)
		return 0; /* No results. */

	ud = lua_newuserdata(L, sizeof(lcores));

	lua_pushcfunction(L, protected_gk_assign_lcores);
	lua_insert(L, 1);

	lcores = rte_malloc("gk_conf.lcores", n * sizeof(*lcores), 0);
	if (lcores == NULL)
		luaL_error(L, "DPDK has run out memory");
	*ud = lcores;

	/* lua_pcall() is used here to avoid leaking @lcores. */
	if (lua_pcall(L, 3, 0, 0)) {
		rte_free(lcores);
		lua_error(L);
	}
	return 0;
}

static int
protected_gk_assign_sol_map(lua_State *L)
{
	uint32_t ctypeid;
	struct gk_config *gk_conf;
	lua_Integer i, n;
	unsigned int *gk_sol_map;

	gk_conf = *(struct gk_config **)
		luaL_checkcdata(L, 1, &ctypeid, CTYPE_STRUCT_GK_CONFIG_PTR);
	n = lua_objlen(L, 2);
	gk_sol_map = *(unsigned int **)lua_touserdata(L, 3);

	for (i = 1; i <= n; i++) {
		lua_pushinteger(L, i);	/* Push i. */
		lua_gettable(L, 2);	/* Pop i, Push t[i]. */

		/* Check that t[i] is a number. */
		if (!lua_isnumber(L, -1))
			luaL_error(L, "Index %d is not a number", i);
		gk_sol_map[i - 1] = lua_tointeger(L, -1) - 1;

		lua_pop(L, 1);		/* Pop t[i]. */
	}

	gk_conf->gk_sol_map = gk_sol_map;
	return 0; /* No results. */
}

static int
l_gk_assign_sol_map(lua_State *L)
{
	uint32_t ctypeid;
	lua_Integer n;
	unsigned int *gk_sol_map, **ud;
	uint32_t correct_ctypeid = luaL_get_ctypeid(L,
		CTYPE_STRUCT_GK_CONFIG_PTR);

	/* First argument must be of type CTYPE_STRUCT_GK_CONFIG_PTR. */
	luaL_checkcdata(L, 1, &ctypeid, CTYPE_STRUCT_GK_CONFIG_PTR);
	if (ctypeid != correct_ctypeid)
		luaL_error(L, "Expected `%s' as first argument",
			CTYPE_STRUCT_GK_CONFIG_PTR);

	/* Second argument must be a table. */
	luaL_checktype(L, 2, LUA_TTABLE);

	n = lua_objlen(L, 2); /* Get size of the table. */
	if (n <= 0)
		return 0; /* No results. */

	ud = lua_newuserdata(L, sizeof(gk_sol_map));

	lua_pushcfunction(L, protected_gk_assign_sol_map);
	lua_insert(L, 1);

	gk_sol_map = rte_malloc("gk_conf.gk_sol_map",
		n * sizeof(*gk_sol_map), 0);
	if (gk_sol_map == NULL)
		luaL_error(L, "DPDK has run out memory");
	*ud = gk_sol_map;

	/* lua_pcall() is used here to avoid leaking @gk_sol_map. */
	if (lua_pcall(L, 3, 0, 0)) {
		rte_free(gk_sol_map);
		lua_error(L);
	}
	return 0;
}

#define CTYPE_STRUCT_GT_CONFIG_PTR "struct gt_config *"

static int
protected_gt_assign_lcores(lua_State *L)
{
	uint32_t ctypeid;
	struct gt_config *gt_conf;
	lua_Integer i, n;
	unsigned int *lcores;

	gt_conf = *(struct gt_config **)
		luaL_checkcdata(L, 1, &ctypeid, CTYPE_STRUCT_GT_CONFIG_PTR);
	n = lua_objlen(L, 2);
	lcores = *(unsigned int **)lua_touserdata(L, 3);

	for (i = 1; i <= n; i++) {
		lua_pushinteger(L, i);	/* Push i. */
		lua_gettable(L, 2);	/* Pop i, Push t[i]. */

		/* Check that t[i] is a number. */
		if (!lua_isnumber(L, -1))
			luaL_error(L, "Index %d is not a number", i);
		lcores[i - 1] = lua_tointeger(L, -1);

		lua_pop(L, 1);		/* Pop t[i]. */
	}

	gt_conf->lcores = lcores;
	gt_conf->num_lcores = n;
	return 0; /* No results. */
}

static int
l_gt_assign_lcores(lua_State *L)
{
	uint32_t ctypeid;
	lua_Integer n;
	unsigned int *lcores, **ud;
	uint32_t correct_ctypeid = luaL_get_ctypeid(L,
		CTYPE_STRUCT_GT_CONFIG_PTR);

	/* First argument must be of type CTYPE_STRUCT_GT_CONFIG_PTR. */
	luaL_checkcdata(L, 1, &ctypeid, CTYPE_STRUCT_GT_CONFIG_PTR);
	if (ctypeid != correct_ctypeid)
		luaL_error(L, "Expected `%s' as first argument",
			CTYPE_STRUCT_GT_CONFIG_PTR);

	/* Second argument must be a table. */
	luaL_checktype(L, 2, LUA_TTABLE);

	n = lua_objlen(L, 2); /* Get size of the table. */
	if (n <= 0)
		return 0; /* No results. */

	ud = lua_newuserdata(L, sizeof(lcores));

	lua_pushcfunction(L, protected_gt_assign_lcores);
	lua_insert(L, 1);

	lcores = rte_malloc("gt_conf.lcores", n * sizeof(*lcores), 0);
	if (lcores == NULL)
		luaL_error(L, "DPDK has run out memory");
	*ud = lcores;

	/* lua_pcall() is used here to avoid leaking @lcores. */
	if (lua_pcall(L, 3, 0, 0)) {
		rte_free(lcores);
		lua_error(L);
	}
	return 0;
}

#define CTYPE_STRUCT_SOL_CONFIG_PTR "struct sol_config *"

static int
protected_sol_assign_lcores(lua_State *L)
{
	uint32_t ctypeid;
	struct sol_config *sol_conf;
	lua_Integer i, n;
	unsigned int *lcores;

	sol_conf = *(struct sol_config **)
		luaL_checkcdata(L, 1, &ctypeid, CTYPE_STRUCT_SOL_CONFIG_PTR);
	n = lua_objlen(L, 2);
	lcores = *(unsigned int **)lua_touserdata(L, 3);

	for (i = 1; i <= n; i++) {
		lua_pushinteger(L, i);	/* Push i. */
		lua_gettable(L, 2);	/* Pop i, Push t[i]. */

		/* Check that t[i] is a number. */
		if (!lua_isnumber(L, -1))
			luaL_error(L, "Index %d is not a number", i);
		lcores[i - 1] = lua_tointeger(L, -1);

		lua_pop(L, 1);		/* Pop t[i]. */
	}

	sol_conf->lcores = lcores;
	sol_conf->num_lcores = n;
	return 0; /* No results. */
}

static int
l_sol_assign_lcores(lua_State *L)
{
	uint32_t ctypeid;
	lua_Integer n;
	unsigned int *lcores, **ud;
	uint32_t correct_ctypeid = luaL_get_ctypeid(L,
		CTYPE_STRUCT_SOL_CONFIG_PTR);

	/* First argument must be of type CTYPE_STRUCT_SOL_CONFIG_PTR. */
	luaL_checkcdata(L, 1, &ctypeid, CTYPE_STRUCT_SOL_CONFIG_PTR);
	if (ctypeid != correct_ctypeid)
		luaL_error(L, "Expected `%s' as first argument",
			CTYPE_STRUCT_SOL_CONFIG_PTR);

	/* Second argument must be a table. */
	luaL_checktype(L, 2, LUA_TTABLE);

	n = lua_objlen(L, 2); /* Get size of the table. */
	if (n <= 0)
		return 0; /* No results. */

	ud = lua_newuserdata(L, sizeof(lcores));

	lua_pushcfunction(L, protected_sol_assign_lcores);
	lua_insert(L, 1);

	lcores = rte_malloc("sol_conf.lcores", n * sizeof(*lcores), 0);
	if (lcores == NULL)
		luaL_error(L, "DPDK has run out memory");
	*ud = lcores;

	/* lua_pcall() is used here to avoid leaking @lcores. */
	if (lua_pcall(L, 3, 0, 0)) {
		rte_free(lcores);
		lua_error(L);
	}
	return 0;
}

static const struct luaL_reg staticlib [] = {
	{"list_lcores",			l_list_lcores},
	{"rte_lcore_to_socket_id",	l_rte_lcore_to_socket_id},
	{"gk_assign_lcores",		l_gk_assign_lcores},
	{"gk_assign_sol_map",		l_gk_assign_sol_map},
	{"gt_assign_lcores",		l_gt_assign_lcores},
	{"sol_assign_lcores",		l_sol_assign_lcores},
	{NULL,				NULL}	/* Sentinel. */
};

int
set_lua_path(lua_State *L, const char *path)
{
	int ret;
	char new_path[1024];

	lua_getglobal(L, "package");
	lua_getfield(L, -1, "path");

	ret = snprintf(new_path, sizeof(new_path), "%s;%s/?.lua",
		lua_tostring(L, -1), path);
	RTE_VERIFY(ret > 0 && ret < (int)sizeof(new_path));

	lua_pop(L, 1);
	lua_pushstring(L, new_path);
	lua_setfield(L, -2, "path");
	lua_pop(L, 1);

	return ret;
}

int
config_gatekeeper(const char *lua_base_dir, const char *gatekeeper_config_file)
{
	int ret;
	char lua_entry_path[128];
	lua_State *lua_state;

	ret = snprintf(lua_entry_path, sizeof(lua_entry_path), \
			"%s/%s", lua_base_dir, gatekeeper_config_file);
	RTE_VERIFY(ret > 0 && ret < (int)sizeof(lua_entry_path));

	lua_state = luaL_newstate();
	if (!lua_state) {
		G_LOG(ERR, "config: failed to create new Lua state\n");
		return -1;
	}

	luaL_openlibs(lua_state);
	luaL_register(lua_state, "staticlib", staticlib);
	set_lua_path(lua_state, lua_base_dir);
	ret = luaL_loadfile(lua_state, lua_entry_path);
	if (ret != 0) {
		G_LOG(ERR, "config: %s\n", lua_tostring(lua_state, -1));
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
		G_LOG(ERR, "config: %s\n", lua_tostring(lua_state, -1));
		ret = -1;
		goto out;
	}

	/* Function to be called. */
	lua_getglobal(lua_state, "gatekeeper_init");
	ret = lua_pcall(lua_state, 0, 1, 0);
	if (ret != 0) {
		G_LOG(ERR, "config: %s\n", lua_tostring(lua_state, -1));
		ret = -1;
		goto out;
	}

	ret = lua_tointeger(lua_state, -1);
	if (ret != 1)
		G_LOG(ERR, "config: gatekeeper_init() return value is %d\n",
			ret);
	lua_pop(lua_state, 1);

out:
	lua_close(lua_state);
	return ret;
}
