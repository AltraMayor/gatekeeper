return function (net_conf, numa_table)

	-- Init the GT configuration structure.
	local gt_conf = gatekeeper.c.alloc_gt_conf()
	if gt_conf == nil then
		error("Failed to allocate gt_conf")
	end
	
	-- Change these parameters to configure the Grantor.
	local n_lcores = 2

	local gt_lcores = gatekeeper.alloc_lcores_from_same_numa(numa_table,
		n_lcores)
	gatekeeper.gt_assign_lcores(gt_conf, gt_lcores)

	-- Setup the GT functional block.
	local ret = gatekeeper.c.run_gt(net_conf, gt_conf)
	if ret < 0 then
		error("Failed to run gt block(s)")
	end

	return gt_conf
end
