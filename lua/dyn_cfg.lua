return function (numa_table)

	-- Init the dynamic configuration structure.
	local dy_conf = gatekeeper.c.get_dy_conf()
	if dy_conf == nil then
		error("Failed to allocate dy_conf")
	end

	local server_path = "/tmp/dyn_cfg.socket"

	dy_conf.lcore_id = gatekeeper.alloc_an_lcore(numa_table)

	gatekeeper.c.set_dyc_timeout(30, 0, dy_conf)

	-- Setup the dynamic config functional block.
	local ret = gatekeeper.c.run_dynamic_config(server_path, dy_conf)
	if ret < 0 then
		error("Failed to run dynamic config block")
	end

	return dy_conf
end
