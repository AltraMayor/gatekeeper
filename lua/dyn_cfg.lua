return function (gk_conf, gt_conf, numa_table)

	--
	-- Configure the variables below for the Dynamic Config block.
	--

	-- These parameters should likely be initially changed.
	local log_level = staticlib.c.RTE_LOG_DEBUG

	-- XXX #155 These parameters should only be changed for performance reasons.
	local log_ratelimit_interval_ms = 5000
	local log_ratelimit_burst = 10

	-- These variables are unlikely to need to be changed.
	local server_path = "/tmp/dyn_cfg.socket"
	local lua_dy_base_dir = "./lua"
	local lua_dy_lib = "gatekeeper/dylib.lua"
	local rcv_timeout_sec = 30
	local rcv_timeout_usec = 0

	--
	-- End configuration of Dynamic Config block.
	--

	local dy_conf = staticlib.c.get_dy_conf()
	if dy_conf == nil then
		error("Failed to allocate dy_conf")
	end

	dy_conf.lcore_id = staticlib.alloc_an_lcore(numa_table)

	dy_conf.log_level = log_level

	dy_conf.log_ratelimit_interval_ms = log_ratelimit_interval_ms
	dy_conf.log_ratelimit_burst = log_ratelimit_burst

	staticlib.c.set_dyc_timeout(rcv_timeout_sec,
		rcv_timeout_usec, dy_conf)

	local ret = staticlib.c.run_dynamic_config(
		gk_conf, gt_conf, server_path,
		lua_dy_base_dir, lua_dy_lib, dy_conf)
	if ret < 0 then
		error("Failed to run dynamic config block")
	end

	return dy_conf
end
