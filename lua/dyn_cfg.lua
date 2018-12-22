return function (gk_conf, gt_conf, numa_table)

	-- Init the dynamic configuration structure.
	local dy_conf = gatekeeper.c.get_dy_conf()
	if dy_conf == nil then
		error("Failed to allocate dy_conf")
	end

	local server_path = "/tmp/dyn_cfg.socket"
	local lua_dy_base_dir = "./lua"
	local dynamic_config_file = "dylib.lua"

	dy_conf.lcore_id = gatekeeper.alloc_an_lcore(numa_table)

	-- Log level for Dynamic Configuration.
	dy_conf.log_level = gatekeeper.c.RTE_LOG_DEBUG

	gatekeeper.c.set_dyc_timeout(30, 0, dy_conf)

	-- Setup the dynamic config functional block.
	local ret = gatekeeper.c.run_dynamic_config(
		gk_conf, gt_conf, server_path,
		lua_dy_base_dir, dynamic_config_file, dy_conf)
	if ret < 0 then
		error("Failed to run dynamic config block")
	end

	return dy_conf
end
