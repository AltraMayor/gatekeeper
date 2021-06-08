require "gatekeeper/staticlib"

local dyc = staticlib.c.get_dy_conf()
if dyc == nil then
	return "No dynamic configuration block available"
end
if dyc.gk == nil then
	return "No GK block available; not a Gatekeeper server"
end

local function print_only_grantor(fib_dump_entry, acc)
	if fib_dump_entry.action ~= dylib.c.GK_FWD_GRANTOR then
		return false, acc
	end
	return dylib.print_fib_dump_entry(fib_dump_entry, acc)
end

return table.concat(dylib.list_gk_fib6(dyc.gk, print_only_grantor, {}))
