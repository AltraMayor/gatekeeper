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

#include <arpa/inet.h>
#include <lauxlib.h>

#include <rte_lcore.h>

#include "lua_lpm.h"
#include "luajit-ffi-cdata.h"
#include "gatekeeper_net.h"
#include "gatekeeper_lpm.h"
#include "gatekeeper_fib.h"

static int
l_str_to_prefix(lua_State *l)
{
	int ret;
	struct ipaddr ip_addr;

	/* First argument must be an IP prefix string. */
	const char *prefix_str = luaL_checkstring(l, 1);

	if (lua_gettop(l) != 1)
		luaL_error(l, "Expected one argument, however it got %d arguments",
			lua_gettop(l));

	ret = parse_ip_prefix(prefix_str, &ip_addr);
	if (ret < 0 || ip_addr.proto != RTE_ETHER_TYPE_IPV4)
		luaL_error(l, "gk: failed to parse an IPv4 prefix");

	lua_pushinteger(l, ip_addr.ip.v4.s_addr);
	lua_pushinteger(l, ret);

	return 2;
}

#define CTYPE_STRUCT_IN6_ADDR_REF "struct in6_addr &"
#define CTYPE_STRUCT_IN6_ADDR "struct in6_addr"

static int
l_str_to_prefix6(lua_State *l)
{
	int ret;
	struct ipaddr ip_addr;
	struct in6_addr *cdata;
	uint32_t correct_ctypeid_in6_addr;

	/* First argument must be an IP prefix string. */
	const char *prefix_str = luaL_checkstring(l, 1);

	if (lua_gettop(l) != 1)
		luaL_error(l, "Expected one argument, however it got %d arguments",
			lua_gettop(l));

	ret = parse_ip_prefix(prefix_str, &ip_addr);
	if (ret < 0 || ip_addr.proto != RTE_ETHER_TYPE_IPV6)
		luaL_error(l, "gk: failed to parse an IPv6 prefix");

	correct_ctypeid_in6_addr = luaL_get_ctypeid(l,
		CTYPE_STRUCT_IN6_ADDR);
	cdata = luaL_pushcdata(l, correct_ctypeid_in6_addr,
		sizeof(struct in6_addr));
	*cdata = ip_addr.ip.v6;

	lua_pushinteger(l, ret);

	return 2;
}

#define LUA_LPM_TNAME "gt_lpm"

static int
l_new_lpm(lua_State *l)
{
	struct rte_lpm_config lpm_conf;
	struct rte_lpm **p_lpm;
	static rte_atomic32_t identifier = RTE_ATOMIC32_INIT(0);

	memset(&lpm_conf, 0, sizeof(lpm_conf));

	/* First argument must be a Lua number. */
	lpm_conf.max_rules = luaL_checknumber(l, 1);

	/* Second argument must be a Lua number. */
	lpm_conf.number_tbl8s = luaL_checknumber(l, 2);

	if (lua_gettop(l) != 2)
		luaL_error(l, "Expected two arguments, however it got %d arguments",
			lua_gettop(l));

	p_lpm = lua_newuserdata(l, sizeof(struct rte_lpm *));
	*p_lpm = init_ipv4_lpm("gt_", &lpm_conf, rte_socket_id(),
		rte_lcore_id(), rte_atomic32_add_return(&identifier, 1));
	if (unlikely(*p_lpm == NULL))
		luaL_error(l, "gt: failed to initialize the IPv4 LPM table for Lua policies");

	luaL_getmetatable(l, LUA_LPM_TNAME);
	lua_setmetatable(l, -2);

	return 1;
}

static int
l_lpm_add(lua_State *l)
{
	int ret;

	/* First argument must be of type struct rte_lpm **. */
	struct rte_lpm *lpm =
		*(struct rte_lpm **)luaL_checkudata(l, 1, LUA_LPM_TNAME);

	/*
	 * Second argument must be a Lua number.
	 * @ip must be in network order.
	 */
	uint32_t ip = luaL_checknumber(l, 2);

	/* Third argument must be a Lua number. */
	uint8_t depth = luaL_checknumber(l, 3);

	/* Fourth argument must be a Lua number. */
	uint32_t label = luaL_checknumber(l, 4);

	if (lua_gettop(l) != 4)
		luaL_error(l, "Expected four arguments, however it got %d arguments",
			lua_gettop(l));

	ret = rte_lpm_add(lpm, ntohl(ip), depth, label);
	if (ret < 0) {
		luaL_error(l, "lpm: failed to add network policy [ip: %d, depth: %d, label: %d] to the lpm table at %s",
			ip, depth, label, __func__);
	}

	return 0;
}

static int
l_lpm_del(lua_State *l)
{
	/* First argument must be of type struct rte_lpm **. */
	struct rte_lpm *lpm =
		*(struct rte_lpm **)luaL_checkudata(l, 1, LUA_LPM_TNAME);

	/*
	 * Second argument must be a Lua number.
	 * @ip must be in network order.
	 * */
	uint32_t ip = luaL_checknumber(l, 2);

	/* Third argument must be a Lua number. */
	uint8_t depth = luaL_checknumber(l, 3);

	if (lua_gettop(l) != 3)
		luaL_error(l, "Expected three arguments, however it got %d arguments",
			lua_gettop(l));

	lua_pushinteger(l, rte_lpm_delete(lpm, ntohl(ip), depth));

	return 1;
}

static int
l_lpm_lookup(lua_State *l)
{
	/* First argument must be of type struct rte_lpm **. */
	struct rte_lpm *lpm =
		*(struct rte_lpm **)luaL_checkudata(l, 1, LUA_LPM_TNAME);

	/*
	 * Second argument must be a Lua number.
	 * @ip must be in network order.
	 */
	uint32_t ip = luaL_checknumber(l, 2);

	if (lua_gettop(l) != 2)
		luaL_error(l, "Expected two arguments, however it got %d arguments",
			lua_gettop(l));

	lua_pushinteger(l, lpm_lookup_ipv4(lpm, ip));

	return 1;
}

static int
l_ip_mask_addr(lua_State *l)
{
	uint32_t masked_ip;
	struct in_addr mask;
	char buf[INET_ADDRSTRLEN];

	/*
	 * First argument must be a Lua number.
	 * @ip must be in network order.
	 */
	uint32_t ip = luaL_checknumber(l, 1);

	/* Second argument must be a Lua number. */
	uint8_t depth = luaL_checknumber(l, 2);
	if ((depth == 0) || (depth > RTE_LPM_MAX_DEPTH))
		luaL_error(l, "Expected a depth value between 1 and 32, however it is %d",
			depth);

	if (lua_gettop(l) != 2)
		luaL_error(l, "Expected two arguments, however it got %d arguments",
			lua_gettop(l));

	ip4_prefix_mask(depth, &mask);
	masked_ip = htonl(ntohl(ip) & rte_be_to_cpu_32(mask.s_addr));

	if (inet_ntop(AF_INET, &masked_ip, buf, sizeof(buf)) == NULL)
		luaL_error(l, "%s: failed to convert a number to an IPv4 address (%s)\n",
			__func__, strerror(errno));

	lua_pushstring(l, buf);
	return 1;
}

static int
l_lpm_get_paras(lua_State *l)
{
	/* First argument must be of type struct rte_lpm **. */
	struct rte_lpm *lpm =
		*(struct rte_lpm **)luaL_checkudata(l, 1, LUA_LPM_TNAME);

	if (lua_gettop(l) != 1)
		luaL_error(l, "Expected one argument, however it got %d arguments",
			lua_gettop(l));

	lua_pushinteger(l, lpm->max_rules);
	lua_pushinteger(l, lpm->number_tbl8s);
	return 2;
}

#define LUA_LPM6_TNAME "gt_lpm6"

static int
l_new_lpm6(lua_State *l)
{
	struct rte_lpm6_config lpm6_conf;
	struct rte_lpm6 **p_lpm6;
	static rte_atomic32_t identifier6 = RTE_ATOMIC32_INIT(0);

	memset(&lpm6_conf, 0, sizeof(lpm6_conf));

	/* First argument must be a Lua number. */
	lpm6_conf.max_rules = luaL_checknumber(l, 1);

	/* Second argument must be a Lua number. */
	lpm6_conf.number_tbl8s = luaL_checknumber(l, 2);

	if (lua_gettop(l) != 2)
		luaL_error(l, "Expected two arguments, however it got %d arguments",
			lua_gettop(l));

	p_lpm6 = lua_newuserdata(l, sizeof(struct rte_lpm6 *));
	*p_lpm6 = init_ipv6_lpm("gt", &lpm6_conf, rte_socket_id(),
		rte_lcore_id(), rte_atomic32_add_return(&identifier6, 1));
	if (unlikely(*p_lpm6 == NULL))
		luaL_error(l, "gt: failed to initialize the IPv6 LPM table for Lua policies");

	luaL_getmetatable(l, LUA_LPM6_TNAME);
	lua_setmetatable(l, -2);

	return 1;
}

static int
l_lpm6_add(lua_State *l)
{
	int ret;
	struct in6_addr *ipv6_addr;
	uint8_t depth;
	uint32_t label;
	uint32_t ctypeid;
	uint32_t correct_ctypeid_in6_addr;

	/* First argument must be of type struct rte_lpm6 **. */
	struct rte_lpm6 *lpm6 =
		*(struct rte_lpm6 **)luaL_checkudata(l, 1, LUA_LPM6_TNAME);

	correct_ctypeid_in6_addr = luaL_get_ctypeid(l,
		CTYPE_STRUCT_IN6_ADDR_REF);
	/* Second argument must be of type CTYPE_STRUCT_IN6_ADDR_REF. */
	ipv6_addr = luaL_checkcdata(l, 2, &ctypeid,
		CTYPE_STRUCT_IN6_ADDR_REF);
	if (ctypeid != correct_ctypeid_in6_addr)
		luaL_error(l, "Expected `%s' as second argument",
			CTYPE_STRUCT_IN6_ADDR_REF);

	/* Third argument must be a Lua number. */
	depth = luaL_checknumber(l, 3);

	/* Fourth argument must be a Lua number. */
	label = luaL_checknumber(l, 4);

	if (lua_gettop(l) != 4)
		luaL_error(l, "Expected four arguments, however it got %d arguments",
			lua_gettop(l));

	ret = rte_lpm6_add(lpm6, ipv6_addr->s6_addr, depth, label);
	if (ret < 0) {
		luaL_error(l, "lpm6: failed to add a network policy to the lpm6 table at %s",
			__func__);
	}

	return 0;
}

static int
l_lpm6_del(lua_State *l)
{
	uint8_t depth;
	struct in6_addr *ipv6_addr;
	uint32_t ctypeid;
	uint32_t correct_ctypeid_in6_addr;

	/* First argument must be of type struct rte_lpm6 **. */
	struct rte_lpm6 *lpm6 =
		*(struct rte_lpm6 **)luaL_checkudata(l, 1, LUA_LPM6_TNAME);

	correct_ctypeid_in6_addr = luaL_get_ctypeid(l,
		CTYPE_STRUCT_IN6_ADDR_REF);
	/* Second argument must be of type CTYPE_STRUCT_IN6_ADDR_REF. */
	ipv6_addr = luaL_checkcdata(l, 2, &ctypeid, CTYPE_STRUCT_IN6_ADDR_REF);
	if (ctypeid != correct_ctypeid_in6_addr)
		luaL_error(l, "Expected `%s' as second argument",
			CTYPE_STRUCT_IN6_ADDR_REF);

	/* Third argument must be a Lua number. */
	depth = luaL_checknumber(l, 3);

	if (lua_gettop(l) != 3)
		luaL_error(l, "Expected three arguments, however it got %d arguments",
			lua_gettop(l));

	lua_pushinteger(l, rte_lpm6_delete(lpm6, ipv6_addr->s6_addr, depth));

	return 1;
}

static int
l_lpm6_lookup(lua_State *l)
{
	struct in6_addr *ipv6_addr;
	uint32_t ctypeid;
	uint32_t correct_ctypeid_in6_addr;

	/* First argument must be of type struct rte_lpm6 **. */
	struct rte_lpm6 *lpm6 =
		*(struct rte_lpm6 **)luaL_checkudata(l, 1, LUA_LPM6_TNAME);

	correct_ctypeid_in6_addr = luaL_get_ctypeid(l,
		CTYPE_STRUCT_IN6_ADDR_REF);
	/* Second argument must be of type CTYPE_STRUCT_IN6_ADDR_REF. */
	ipv6_addr = luaL_checkcdata(l, 2, &ctypeid, CTYPE_STRUCT_IN6_ADDR_REF);
	if (ctypeid != correct_ctypeid_in6_addr)
		luaL_error(l, "Expected `%s' as second argument",
			CTYPE_STRUCT_IN6_ADDR_REF);

	if (lua_gettop(l) != 2)
		luaL_error(l, "Expected two arguments, however it got %d arguments",
			lua_gettop(l));

	lua_pushinteger(l, lpm_lookup_ipv6(lpm6, ipv6_addr));

	return 1;
}

/*
 * Takes an array of uint8_t (IPv6 address) and masks it using the depth.
 */
static void
ip6_mask_addr(uint8_t *ip, uint8_t depth)
{
	struct in6_addr mask;
	uint64_t *paddr = (uint64_t *)ip;
	const uint64_t *pmask = (const uint64_t *)mask.s6_addr;

	ip6_prefix_mask(depth, &mask);

	paddr[0] &= pmask[0];
	paddr[1] &= pmask[1];
}

/* Copy ipv6 address. */
static inline void
ip6_copy_addr(uint8_t *dst, const uint8_t *src)
{
	rte_memcpy(dst, src, RTE_LPM6_IPV6_ADDR_SIZE);
}

static int
l_ip6_mask_addr(lua_State *l)
{
	uint8_t depth;
	uint32_t ctypeid;
	uint8_t masked_ip[RTE_LPM6_IPV6_ADDR_SIZE];
	char buf[INET6_ADDRSTRLEN];

	uint32_t correct_ctypeid_in6_addr = luaL_get_ctypeid(l,
		CTYPE_STRUCT_IN6_ADDR_REF);
	/* First argument must be of type CTYPE_STRUCT_IN6_ADDR_REF. */
	struct in6_addr *ipv6_addr = luaL_checkcdata(l, 1, &ctypeid,
		CTYPE_STRUCT_IN6_ADDR_REF);
	if (ctypeid != correct_ctypeid_in6_addr)
		luaL_error(l, "Expected `%s' as first argument",
			CTYPE_STRUCT_IN6_ADDR_REF);

	/* Second argument must be a Lua number. */
	depth = luaL_checknumber(l, 2);
	if ((depth == 0) || (depth > RTE_LPM6_MAX_DEPTH))
		luaL_error(l, "Expected a depth value between 1 and 128, however it is %d",
			depth);

	if (lua_gettop(l) != 2)
		luaL_error(l, "Expected two arguments, however it got %d arguments",
			lua_gettop(l));

	ip6_copy_addr(masked_ip, ipv6_addr->s6_addr);
	ip6_mask_addr(masked_ip, depth);

	if (inet_ntop(AF_INET6, masked_ip, buf, sizeof(buf)) == NULL)
		luaL_error(l, "net: %s: failed to convert a number to an IPv6 address (%s)\n",
			__func__, strerror(errno));

	lua_pushstring(l, buf);
	return 1;
}

static int
l_lpm6_get_paras(lua_State *l)
{
	/* First argument must be of type struct rte_lpm6 **. */
	struct rte_lpm6 *lpm6 =
		*(struct rte_lpm6 **)luaL_checkudata(l, 1, LUA_LPM6_TNAME);

	if (lua_gettop(l) != 1)
		luaL_error(l, "Expected one argument, however it got %d arguments",
			lua_gettop(l));

	lua_pushinteger(l, rte_lpm6_get_max_rules(lpm6));
	lua_pushinteger(l, rte_lpm6_get_num_tbl8s(lpm6));
	return 2;
}

static const struct luaL_reg lpmlib_lua_c_funcs [] = {
	{"str_to_prefix",  l_str_to_prefix},
	{"new_lpm",        l_new_lpm},
	{"lpm_add",        l_lpm_add},
	{"lpm_del",        l_lpm_del},
	{"lpm_lookup",     l_lpm_lookup},
	{"ip_mask_addr",   l_ip_mask_addr},
	{"lpm_get_paras",  l_lpm_get_paras},
	{"str_to_prefix6", l_str_to_prefix6},
	{"new_lpm6",       l_new_lpm6},
	{"lpm6_add",       l_lpm6_add},
	{"lpm6_del",       l_lpm6_del},
	{"lpm6_lookup",    l_lpm6_lookup},
	{"ip6_mask_addr",  l_ip6_mask_addr},
	{"lpm6_get_paras", l_lpm6_get_paras},
	{NULL,             NULL}	/* Sentinel. */
};

static int
lpm_gc(lua_State *l) {
	struct rte_lpm *lpm = *(struct rte_lpm **)lua_touserdata(l, 1);
	rte_lpm_free(lpm);
	return 0;
}

static int
lpm6_gc(lua_State *l) {
	struct rte_lpm6 *lpm6 = *(struct rte_lpm6 **)lua_touserdata(l, 1);
	rte_lpm6_free(lpm6);
	return 0;
}

void
lualpm_openlib(lua_State *l) {
	luaL_newmetatable(l, LUA_LPM_TNAME);
	lua_pushstring(l, "__gc");
	lua_pushcfunction(l, lpm_gc);
	lua_settable(l, -3);

	luaL_newmetatable(l, LUA_LPM6_TNAME);
	lua_pushstring(l, "__gc");
	lua_pushcfunction(l, lpm6_gc);
	lua_settable(l, -3);

	luaL_register(l, "lpmlib", lpmlib_lua_c_funcs);
}
