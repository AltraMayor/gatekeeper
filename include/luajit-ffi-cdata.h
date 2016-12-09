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

#ifndef _LUAJIT_FFI_CDATA_H_
#define _LUAJIT_FFI_CDATA_H_

#include <stdint.h>
#include <lua.h>

void *
luaL_pushcdata(struct lua_State *l, uint32_t ctypeid, uint32_t size);

void *
luaL_checkcdata(struct lua_State *l, int idx, uint32_t *ctypeid,
	const char *ctypename);

/* Execute ffi.cdef before first calling luaL_get_ctypeid()! */
uint32_t
luaL_get_ctypeid(struct lua_State *l, const char *ctypename);

#if 0

/*
 * Code example
 */

struct request;

/*
 * ATTENTION: Execute ffi.cdef on struct request here!
 *
 * Example:
 *
 * ffi.cdef([[
 *	-- From request.h.
 *	struct request
 *	{
 *		-- Some members.
 *	};
 * ]])
 *
 * From now on, one can call luaL_get_ctypeid() on "struct request".
 */

/* Get CTIDs calling luaL_get_ctypeid(). */
const uint32_t CTID_STRUCT_REQUEST = luaL_get_ctypeid(l, "struct request");
const uint32_t CTID_STRUCT_REQUEST_PTR =
	luaL_get_ctypeid(l, "struct request *");
const uint32_t CTID_STRUCT_REQUEST_REF =
	luaL_get_ctypeid(l, "struct request &");
const uint32_t CTID_CONST_STRUCT_REQUEST =
	luaL_get_ctypeid(l, "const struct request");
const uint32_t CTID_CONST_STRUCT_REQUEST_PTR =
	luaL_get_ctypeid(l, "const struct request *");
const uint32_t CTID_CONST_STRUCT_REQUEST_REF =
	luaL_get_ctypeid(l, "const struct request &");

static void
pushrequest(struct lua_State *l, const struct request *request)
{
	void *cdata = luaL_pushcdata(l, CTID_CONST_STRUCT_REQUEST_REF,
		sizeof(request));
	*(const struct request **)cdata = request;
}

static const struct request *
checkrequest(struct lua_State *l, int idx)
{
	uint32_t ctypeid;
	void *cdata = luaL_checkcdata(l, idx, &ctypeid, "struct request");

	if (ctypeid == CTID_STRUCT_REQUEST ||
			ctypeid == CTID_CONST_STRUCT_REQUEST) {
		return (const struct request *)cdata;
	} else if (ctypeid == CTID_CONST_STRUCT_REQUEST_REF ||
			ctypeid == CTID_CONST_STRUCT_REQUEST_PTR ||
			ctypeid == CTID_STRUCT_REQUEST_REF ||
			ctypeid == CTID_STRUCT_REQUEST_PTR) {
		return *(const struct request **)cdata;
	}

	luaL_error(l, "expected 'struct request' as %d argument", idx);
	return NULL;
}

#endif /* Code example. */

#endif /* _LUAJIT_FFI_CDATA_H_ */
