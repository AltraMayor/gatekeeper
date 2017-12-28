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

/*
 * The code in this file is based on Roman Tsisyk's gist:
 * An example how to work with CDATA (LuaJIT FFI) objects using lua_State
 * https://gist.github.com/rtsisyk/6103290
 *
 * The code has been changed to compile as a library, to comply to
 * DPDK coding style, and to match the needs of Gatekeeper.
 */

#include <assert.h>
#include <lauxlib.h>

/* luajit's internal headers. */
#include "../dependencies/luajit-2.0/src/lj_ctype.h"
#include "../dependencies/luajit-2.0/src/lj_cdata.h"
#include "../dependencies/luajit-2.0/src/lj_cconv.h"
#include "../dependencies/luajit-2.0/src/lj_state.h"

#include "luajit-ffi-cdata.h"

void *
luaL_pushcdata(struct lua_State *l, uint32_t ctypeid, uint32_t size)
{
	CTState *cts = ctype_cts(l);
	CType *ct = ctype_raw(cts, ctypeid);
	CTSize sz;
	GCcdata *cd;
	TValue *o;

	/* ctypeid actually is CTypeID type.
	 * We don't use CTypeID type outside this file in order to
	 * avoid having to add an internal header of luajit.
	 */
	static_assert(sizeof(ctypeid) == sizeof(CTypeID),
		"sizeof(ctypeid) != sizeof(CTypeID)");

	lj_ctype_info(cts, ctypeid, &sz);
	cd = lj_cdata_new(cts, ctypeid, size);
	o = l->top;
	setcdataV(l, o, cd);
	lj_cconv_ct_init(cts, ct, sz, (uint8_t *) cdataptr(cd), o, 0);
	incr_top(l);
	return cdataptr(cd);
}

void *
luaL_checkcdata(struct lua_State *l, int idx, uint32_t *ctypeid,
	const char *ctypename)
{
	GCcdata *cd;

	/* Calculate absolute value in the stack. */
	if (idx < 0)
		idx = lua_gettop(l) + idx + 1;

	if (lua_type(l, idx) != LUA_TCDATA) {
		luaL_error(l, "expected cdata `%s' as argument #%d",
			ctypename, idx);
		return NULL;
	}

	cd = cdataV(l->base + idx - 1);
	*ctypeid = cd->ctypeid;
	return (void *)cdataptr(cd);
}

uint32_t
luaL_get_ctypeid(struct lua_State *l, const char *ctypename)
{
	int idx = lua_gettop(l);
	CTypeID ctypeid;
	GCcdata *cd;

	/* Get a reference to ffi.typeof. */
	luaL_loadstring(l, "return require('ffi').typeof");
	lua_call(l, 0, 1);
	if (!lua_isfunction(l, -1))
		luaL_error(l,
			"%s: can't get a reference to ffi.typeof", __func__);

	lua_pushstring(l, ctypename);

	if (lua_pcall(l, 1, 1, 0)) {
		if (lua_isstring(l, -1))
			lua_error(l);
		goto fail;
	}

	/* Returned type should be LUA_TCDATA. */
	if (lua_type(l, -1) != LUA_TCDATA)
		goto fail;
	cd = cdataV(l->base + lua_gettop(l) - 1);
	ctypeid = cd->ctypeid == CTID_CTYPEID
		? *(CTypeID *)cdataptr(cd)
		: cd->ctypeid;

	lua_settop(l, idx);
	return ctypeid;

fail:
	return luaL_error(l, "Lua call to ffi.typeof failed");
}
