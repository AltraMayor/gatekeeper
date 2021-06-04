require "gatekeeper/staticlib"

local llsc = staticlib.c.get_lls_conf()
if llsc == nil then
	return "No link layer support block available"
end
return table.concat(dylib.list_lls_arp(llsc, dylib.print_lls_dump_entry, {}))
