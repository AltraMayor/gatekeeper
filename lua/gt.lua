return function (net_conf, numa_table)

	-- Init the GT configuration structure.
	local gt_conf = gatekeeper.c.alloc_gt_conf()
	if gt_conf == nil then
		error("Failed to allocate gt_conf")
	end
	
	-- Change these parameters to configure the Grantor.
	gt_conf.ggu_src_port = 0xA0A0
	gt_conf.ggu_dst_port = 0xB0B0
	gt_conf.frag_bucket_num = 0x1000;
	gt_conf.frag_bucket_entries = 4;
	gt_conf.frag_max_entries = 0x1000;
	gt_conf.frag_max_flow_ttl_ms = 1000;

	-- Scan the whole fragment table in 2 minutes.
	gt_conf.frag_scan_timeout_ms = math.floor(
		2 * 60 * 1000 / gt_conf.frag_bucket_num + 0.5)

	local n_lcores = 2

	local gt_lcores = gatekeeper.alloc_lcores_from_same_numa(numa_table,
		n_lcores)
	gatekeeper.gt_assign_lcores(gt_conf, gt_lcores)

	gt_conf.max_num_ipv6_neighbors = 1024

	-- Setup the GT functional block.
	local ret = gatekeeper.c.run_gt(net_conf, gt_conf)
	if ret < 0 then
		error("Failed to run gt block(s)")
	end

	return gt_conf
end
