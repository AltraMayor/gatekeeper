require "gatekeeper/staticlib"

local dyc = staticlib.c.get_dy_conf()
if dyc == nil then
	return "No dynamic configuration block available"
end
if dyc.gt == nil then
	return "No GT block available; not a Grator server"
end

dylib.update_gt_lua_states(dyc.gt)
return "Successfully reloaded the Lua policy"
