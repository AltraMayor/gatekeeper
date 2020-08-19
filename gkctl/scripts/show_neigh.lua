require "gatekeeper/staticlib"

local dyc = staticlib.c.get_dy_conf()
if dyc == nil then
	return "No dynamic configuration block available"
end
if dyc.gk == nil then
	return "No GK block available; not a Gatekeeper server"
end
return dylib.list_gk_neighbors4(dyc.gk, dylib.print_neighbor_dump_entry, "")
