require "gatekeeper/staticlib"

local acc_start = ""
local reply_msg = ""

local dyc = staticlib.c.get_dy_conf()

if dyc.gt ~= nil then
	local function example()
		print("Hello Gatekeeper!")
	end

	dylib.update_gt_lua_states(dyc.gt)
	dylib.update_gt_lua_states_incrementally(dyc.gt, example)
	return "gt: successfully updated the lua states\n"
end

local ret = dylib.c.add_fib_entry("198.51.100.0/24", "203.0.113.1",
	"10.0.2.253", dylib.c.GK_FWD_GRANTOR, dyc.gk)
if ret < 0 then
	return "gk: failed to add an FIB entry\n"
end

-- Examples of temporarily changing global and block log levels.
local old_log_level = staticlib.c.rte_log_get_global_level()
staticlib.c.rte_log_set_global_level(staticlib.c.RTE_LOG_ERR)

local cpsc = staticlib.c.get_cps_conf()
if cpsc == nil then
	return "cps: failed to fetch config to update log level"
end

local old_cps_log_level = staticlib.c.rte_log_get_level(cpsc.log_type)
if old_cps_log_level < 0 then
	return "cps: failed to fetch log level"
end

ret = staticlib.c.rte_log_set_level(cpsc.log_type, staticlib.c.RTE_LOG_ERR)
if ret < 0 then
	return "cps: failed to set new log level"
end

ret = dylib.c.add_fib_entry("192.0.2.0/24", nil,
	"10.0.2.254", dylib.c.GK_FWD_GATEWAY_BACK_NET, dyc.gk)
if ret < 0 then
	return "gk: failed to add an FIB entry\n"
end

-- Revert log levels.
staticlib.c.rte_log_set_global_level(old_log_level)
ret = staticlib.c.rte_log_set_level(cpsc.log_type, old_cps_log_level)
if ret < 0 then
	return "cps: failed to revert to old log level"
end

ret = dylib.c.add_fib_entry("198.18.0.0/15", nil,
	"10.0.1.254", dylib.c.GK_FWD_GATEWAY_FRONT_NET, dyc.gk)
if ret < 0 then
	return "gk: failed to add an FIB entry\n"
end

local ret = dylib.c.add_fib_entry("2001:db8:3::/48", "2001:db8:0::1",
	"2001:db8:2::253", dylib.c.GK_FWD_GRANTOR, dyc.gk)
if ret < 0 then
	return "gk: failed to add an FIB entry\n"
end

ret = dylib.c.add_fib_entry("2001:db8:4::/48", nil,
	"2001:db8:2::253", dylib.c.GK_FWD_GATEWAY_BACK_NET, dyc.gk)
if ret < 0 then
	return "gk: failed to add an FIB entry\n"
end

ret = dylib.c.add_fib_entry("2001:db8:5::/48", nil,
	"2001:db8:1::253", dylib.c.GK_FWD_GATEWAY_FRONT_NET, dyc.gk)
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

ret = dylib.c.del_fib_entry("198.51.100.0/24", dyc.gk)
if ret < 0 then
	return "gk: failed to delete an FIB entry\n"
end

ret = dylib.c.del_fib_entry("192.0.2.0/24", dyc.gk)
if ret < 0 then
	return "gk: failed to delete an FIB entry\n"
end

ret = dylib.c.del_fib_entry("198.18.0.0/15", dyc.gk)
if ret < 0 then
	return "gk: failed to delete an FIB entry\n"
end

ret = dylib.c.del_fib_entry("2001:db8:3::/48", dyc.gk)
if ret < 0 then
	return "gk: failed to delete an FIB entry\n"
end

ret = dylib.c.del_fib_entry("2001:db8:4::/48", dyc.gk)
if ret < 0 then
	return "gk: failed to delete an FIB entry\n"
end

ret = dylib.c.del_fib_entry("2001:db8:5::/48", dyc.gk)
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

local llsc = staticlib.c.get_lls_conf()
if cpsc == nil then
	return "lls: failed to fetch config to dump caches"
end
reply_msg = reply_msg .. dylib.list_lls_arp(llsc,
	dylib.print_lls_dump_entry, acc_start)
reply_msg = reply_msg .. dylib.list_lls_nd(llsc,
	dylib.print_lls_dump_entry, acc_start)

ret = dylib.c.gk_flush_flow_table("198.51.100.0/24", "192.0.2.0/24", dyc.gk)
if ret < 0 then
	return "gk: failed to flush the flow table\n"
end

ret = dylib.c.gk_flush_flow_table("2001:db8:3::/48", "2001:db8:5::/48", dyc.gk)
if ret < 0 then
	return "gk: failed to flush the flow table\n"
end

return "gk: successfully processed all the FIB entries\n" .. reply_msg
