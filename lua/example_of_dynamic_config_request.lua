-- TODO #67 Add examples for other operations. For example:
-- Functions to list the ARP table.
-- Functions to list the ND table.
-- Functions to process the GT policies.
-- ......

require "dylib"

local acc_start = ""
local reply_msg = ""

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

-- Examples of temporarily changing global and block log levels.
local old_log_level = gatekeeper.c.rte_log_get_global_level()
gatekeeper.c.rte_log_set_global_level(gatekeeper.c.RTE_LOG_ERR)

local cpsc = gatekeeper.c.get_cps_conf()
if cpsc == nil then
	return "cps: failed to fetch config to update log level"
end

local old_cps_log_level = gatekeeper.c.rte_log_get_level(cpsc.log_type)
if old_cps_log_level < 0 then
	return "cps: failed to fetch log level"
end

ret = gatekeeper.c.rte_log_set_level(cpsc.log_type, gatekeeper.c.RTE_LOG_ERR)
if ret < 0 then
	return "cps: failed to set new log level"
end

ret = dylib.c.add_fib_entry("100.0.0.1/30", nil,
	"10.0.1.254", dylib.c.GK_FWD_GATEWAY_BACK_NET, dyc.gk)
if ret < 0 then
	return "gk: failed to add an FIB entry\n"
end

-- Revert log levels.
gatekeeper.c.rte_log_set_global_level(old_log_level)
ret = gatekeeper.c.rte_log_set_level(cpsc.log_type, old_cps_log_level)
if ret < 0 then
	return "cps: failed to revert to old log level"
end

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

reply_msg = reply_msg .. dylib.list_gk_fib4(dyc.gk,
	dylib.print_fib_dump_entry, acc_start)
reply_msg = reply_msg .. dylib.list_gk_fib6(dyc.gk,
	dylib.print_fib_dump_entry, acc_start)

reply_msg = reply_msg .. dylib.list_gk_neighbors4(dyc.gk,
	dylib.print_neighbor_dump_entry, acc_start)
reply_msg = reply_msg .. dylib.list_gk_neighbors6(dyc.gk,
	dylib.print_neighbor_dump_entry, acc_start)

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

reply_msg = reply_msg .. dylib.list_gk_fib4(dyc.gk,
	dylib.print_fib_dump_entry, acc_start)
reply_msg = reply_msg .. dylib.list_gk_fib6(dyc.gk,
	dylib.print_fib_dump_entry, acc_start)

reply_msg = reply_msg .. dylib.list_gk_neighbors4(dyc.gk,
	dylib.print_neighbor_dump_entry, acc_start)
reply_msg = reply_msg .. dylib.list_gk_neighbors6(dyc.gk,
	dylib.print_neighbor_dump_entry, acc_start)

return "gk: successfully processed all the FIB entries\n" .. reply_msg
