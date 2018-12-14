-- TODO Add examples for other operations. For example:
-- Functions to add/del/list the GK FIB entries.
-- Functions to list the ARP table.
-- Functions to list the ND table.
-- Functions to process the GT policies.
-- ......

local dyc = gatekeeper.c.get_dy_conf()

if dyc.gt ~= nil then
	dylib.update_lua_states(dyc.gt)
	return "gt: successfully updated the lua states\n"
end

local ret = dylib.c.add_fib_entry("187.73.40.0/30", "128.197.40.100",
	"10.0.1.253", dylib.c.GK_FWD_GRANTOR, dyc.gk)
if ret < 0 then
	return "gk: failed to add an FIB entry\n"
end

-- Example of temporarily changing global log level.
local old_log_level = gatekeeper.c.rte_log_get_global_level()
gatekeeper.c.rte_log_set_global_level(gatekeeper.c.RTE_LOG_ERR)

ret = dylib.c.add_fib_entry("100.0.0.1/30", nil,
	"10.0.1.254", dylib.c.GK_FWD_GATEWAY_BACK_NET, dyc.gk)
if ret < 0 then
	return "gk: failed to add an FIB entry\n"
end

-- Revert log level.
gatekeeper.c.rte_log_set_global_level(old_log_level)

ret = dylib.c.add_fib_entry("200.0.0.1/30", nil,
	"10.0.0.254", dylib.c.GK_FWD_GATEWAY_FRONT_NET, dyc.gk)
if ret < 0 then
	return "gk: failed to add an FIB entry\n"
end

local ret = dylib.c.add_fib_entry("2007:3ef::1/32", "2000:db8::1",
	"2002:db8::1", dylib.c.GK_FWD_GRANTOR, dyc.gk)
if ret < 0 then
	return "gk: failed to add an FIB entry\n"
end

ret = dylib.c.add_fib_entry("2008:3ef::1/32", nil,
	"2002:db8::1", dylib.c.GK_FWD_GATEWAY_BACK_NET, dyc.gk)
if ret < 0 then
	return "gk: failed to add an FIB entry\n"
end

ret = dylib.c.add_fib_entry("2009:3ef::1/32", nil,
	"2001:db8::1", dylib.c.GK_FWD_GATEWAY_FRONT_NET, dyc.gk)
if ret < 0 then
	return "gk: failed to add an FIB entry\n"
end

ret = dylib.c.del_fib_entry("187.73.40.0/30", dyc.gk)
if ret < 0 then
	return "gk: failed to delete an FIB entry\n"
end

ret = dylib.c.del_fib_entry("100.0.0.1/30", dyc.gk)
if ret < 0 then
	return "gk: failed to delete an FIB entry\n"
end

ret = dylib.c.del_fib_entry("200.0.0.1/30", dyc.gk)
if ret < 0 then
	return "gk: failed to delete an FIB entry\n"
end

ret = dylib.c.del_fib_entry("2007:3ef::1/32", dyc.gk)
if ret < 0 then
	return "gk: failed to delete an FIB entry\n"
end

ret = dylib.c.del_fib_entry("2008:3ef::1/32", dyc.gk)
if ret < 0 then
	return "gk: failed to delete an FIB entry\n"
end

ret = dylib.c.del_fib_entry("2009:3ef::1/32", dyc.gk)
if ret < 0 then
	return "gk: failed to delete an FIB entry\n"
end

return "gk: successfully processed all the FIB entries\n"
