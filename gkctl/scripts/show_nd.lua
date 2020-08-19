require "gatekeeper/staticlib"

local llsc = staticlib.c.get_lls_conf()
if llsc == nil then
	return "No link layer support block available"
end
return dylib.list_lls_nd(llsc, dylib.print_lls_dump_entry, "")
