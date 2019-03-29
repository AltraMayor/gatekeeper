return function (net_conf, lls_conf, numa_table)

	--
	-- Configure the variables below for the GT block.
	--

	-- These parameters should likely be initially changed.
	local n_lcores = 2
	local log_level = staticlib.c.RTE_LOG_DEBUG
	local lua_policy_file = "examples/policy.lua"
	local lua_base_directory = "./lua"

	-- XXX #155 These parameters should only be changed for performance reasons.
	local mailbox_max_entries_exp = 7
	local mailbox_mem_cache_size = 0
	local mailbox_burst_size = 32
	local log_ratelimit_interval_ms = 5000
	local log_ratelimit_burst = 10
	local max_pkt_burst = 32

	local max_num_ipv6_neighbors = 1024

	local frag_bucket_num = 0x1000
	local frag_bucket_entries = 4
	local frag_max_entries = 0x1000
	local frag_max_flow_ttl_ms = 1000          -- (1 second)
	local frag_scan_timeout_ms = 2 * 60 * 1000 -- (2 minutes)

	local batch_interval = 2
	local max_ggu_notify_pkts = 8

	-- These variables are unlikely to need to be changed.
	local ggu_src_port = 0xA0A0
	local ggu_dst_port = 0xB0B0

	--
	-- End configuration of GT block.
	--

	local gt_conf = staticlib.c.alloc_gt_conf()
	if gt_conf == nil then
		error("Failed to allocate gt_conf")
	end

	gt_conf.log_level = log_level

	gt_conf.mailbox_max_entries_exp = mailbox_max_entries_exp
	gt_conf.mailbox_mem_cache_size = mailbox_mem_cache_size
	gt_conf.mailbox_burst_size = mailbox_burst_size
	gt_conf.log_ratelimit_interval_ms = log_ratelimit_interval_ms
	gt_conf.log_ratelimit_burst = log_ratelimit_burst

	gt_conf.max_num_ipv6_neighbors = max_num_ipv6_neighbors

	gt_conf.frag_bucket_num = frag_bucket_num
	gt_conf.frag_bucket_entries = frag_bucket_entries
	gt_conf.frag_max_entries = frag_max_entries
	gt_conf.frag_max_flow_ttl_ms = frag_max_flow_ttl_ms
	gt_conf.frag_scan_timeout_ms = math.floor(
		frag_scan_timeout_ms / gt_conf.frag_bucket_num + 0.5)

	gt_conf.batch_interval = batch_interval
	gt_conf.max_ggu_notify_pkts = max_ggu_notify_pkts

	gt_conf.ggu_src_port = ggu_src_port
	gt_conf.ggu_dst_port = ggu_dst_port

	gt_conf.max_pkt_burst = staticlib.get_front_burst_config(
		max_pkt_burst, net_conf)

	-- The maximum number of ARP or ND packets in LLS submitted by
	-- GK or GT. The code below makes sure that the parameter should
	-- be at least the same with the maximum configured value of GT.
	lls_conf.mailbox_max_pkt_sub =
		math.max(lls_conf.mailbox_max_pkt_sub,
		gt_conf.max_pkt_burst)

	local gt_lcores = staticlib.alloc_lcores_from_same_numa(numa_table,
		n_lcores)
	staticlib.gt_assign_lcores(gt_conf, gt_lcores)

	local ret = staticlib.c.run_gt(net_conf, gt_conf,
		lua_base_directory, lua_policy_file)
	if ret < 0 then
		error("Failed to run gt block(s)")
	end

	return gt_conf
end
