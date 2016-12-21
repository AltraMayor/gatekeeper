local M = {}

-- Function that sets up the GK functional block.
function M.setup_block(net_conf, numa_table)

	-- Init the GK configuration structure.
	local gk_conf = gatekeeper.c.alloc_gk_conf()
	if gk_conf == nil then return nil end
	
	-- Change these parameters to configure the Gatekeeper.
	gk_conf.flow_ht_size = 1024
	local n_lcores = 2

	local gk_lcores = gatekeeper.alloc_lcores_from_same_numa(numa_table,
		n_lcores + 1)
	local ggu_lcore = table.remove(gk_lcores)
	gatekeeper.gk_assign_lcores(gk_conf, gk_lcores)

	-- Setup the GK functional block.
	local ret = gatekeeper.c.run_gk(net_conf, gk_conf)
	if ret < 0 then return nil end

	return gk_conf, ggu_lcore
end

return M
