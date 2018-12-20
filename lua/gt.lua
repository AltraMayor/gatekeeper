return function (net_conf, lls_conf, numa_table)

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
	gt_conf.batch_interval = 2;
	gt_conf.max_ggu_notify_pkts = 8;

	-- Scan the whole fragment table in 2 minutes.
	gt_conf.frag_scan_timeout_ms = math.floor(
		2 * 60 * 1000 / gt_conf.frag_bucket_num + 0.5)

	-- The maximum number of packets to retrieve/transmit.
	local gt_max_pkt_burst = 32

	local n_lcores = 2

	local gt_lcores = gatekeeper.alloc_lcores_from_same_numa(numa_table,
		n_lcores)
	gatekeeper.gt_assign_lcores(gt_conf, gt_lcores)

	gt_conf.max_num_ipv6_neighbors = 1024

	-- Sample parameters, need to be tested for better performance.
	gt_conf.mailbox_max_entries_exp = 7
	gt_conf.mailbox_mem_cache_size = 0
	gt_conf.mailbox_burst_size = 32

	-- Log level for GT.
	gt_conf.log_level = gatekeeper.c.RTE_LOG_DEBUG

	gt_conf.gt_max_pkt_burst = gatekeeper.get_front_burst_config(
		gt_max_pkt_burst, net_conf)
	-- The maximum number of ARP or ND packets in LLS submitted by
	-- GK or GT. The code below makes sure that the parameter should
	-- be at least the same with the maximum configured value of GT.
	lls_conf.mailbox_max_pkt_burst =
		math.max(lls_conf.mailbox_max_pkt_burst,
		gt_conf.gt_max_pkt_burst)

	-- Setup the GT functional block.
	local lua_base_directory = "./lua"
	local lua_policy_file = "policy.lua"
	local ret = gatekeeper.c.run_gt(net_conf, gt_conf,
		lua_base_directory, lua_policy_file)
	if ret < 0 then
		error("Failed to run gt block(s)")
	end

	return gt_conf
end
