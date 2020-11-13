require "gatekeeper/staticlib"

local acc_start = ""
local reply_msg = ""

local dyc = staticlib.c.get_dy_conf()

if dyc.gt ~= nil then
	local function example()
		print("Hello Gatekeeper!")
	end

	dylib.update_gt_lua_states(dyc.gt)
	dylib.update_gt_lua_states_incrementally(dyc.gt, example, false)
	return "gt: successfully updated the lua states\n"
end

local ret = dylib.c.add_fib_entry("198.51.100.0/24", "203.0.113.1",
	"10.0.2.253", dylib.c.GK_FWD_GRANTOR, dyc.gk)
if ret < 0 then
	return "gk: failed to add an FIB entry\n"
end

ret = dylib.c.del_fib_entry("198.51.100.0/24", dyc.gk)
if ret < 0 then
	return "gk: failed to delete an FIB entry\n"
end

-- Load balancing to multiple Grantor servers,
-- where one Grantor is weighted twice as much.
addrs = {
	{ gt_ip = '203.0.113.2', gw_ip = '10.0.2.252' },
	{ gt_ip = '203.0.113.3', gw_ip = '10.0.2.251' },
	{ gt_ip = '203.0.113.4', gw_ip = '10.0.2.250' },
	{ gt_ip = '203.0.113.4', gw_ip = '10.0.2.250' }
}
dylib.add_grantor_entry_lb("198.51.100.0/24", addrs, dyc.gk)

-- Update to make one Grantor weighted 3x as much as the other.
addrs[1] = { gt_ip = '203.0.113.4', gw_ip = '10.0.2.250' }
dylib.update_grantor_entry_lb("198.51.100.0/24", addrs, dyc.gk)

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

ret = dylib.c.gk_log_flow_state("198.51.100.0", "192.0.2.0", dyc.gk)
if ret < 0 then
	return "gk: failed to log the flow state\n"
end

ret = dylib.c.gk_log_flow_state("2001:db8:3::", "2001:db8:5::", dyc.gk)
if ret < 0 then
	return "gk: failed to log the flow state\n"
end

ret = dylib.c.gk_flush_flow_table("198.51.100.0/24", "192.0.2.0/24", dyc.gk)
if ret < 0 then
	return "gk: failed to flush the flow table\n"
end

ret = dylib.c.gk_flush_flow_table("2001:db8:3::/48", "2001:db8:5::/48", dyc.gk)
if ret < 0 then
	return "gk: failed to flush the flow table\n"
end

ret = dylib.c.gk_load_bpf_flow_handler(dyc.gk, 255, "bpf/granted.bpf", true)
if ret < 0 then
	-- The error below may be triggered for a number reasons,
	-- the reasons below should be the most common ones:
	--
	-- 1. This example program runs more than once,
	--	this is an expected error;
	--
	-- 2. Running Gatekeeper in a folder different from
	--	the root of the repository requires to adjust the path passed
	--	to dylib.c.gk_load_bpf_flow_handler();
	--
	-- 3. The BPF programs in folder ROOT_OF_REPOSITORY/bpf are
	--	not compiled.
	return "gk: failed to load a BPF program in runtime"
end

return "gk: successfully processed all the FIB entries\n" .. reply_msg
