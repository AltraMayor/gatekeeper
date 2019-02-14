return function (net_conf, gk_conf, gt_conf, lls_conf, numa_table)

	--
	-- Configure the variables below for the CPS block.
	--

	-- These parameters should likely be initially changed.
	local kni_kmod_path = "/home/user/gatekeeper/dependencies/dpdk/build/kmod/rte_kni.ko"
	local log_level = gatekeeper.c.RTE_LOG_DEBUG

	-- XXX #155 These parameters should only be changed for performance reasons.
	local mailbox_max_entries_exp = 7
	local mailbox_mem_cache_size = 0
	local mailbox_burst_size = 32
	local log_ratelimit_interval_ms = 5000
	local log_ratelimit_burst = 10
	local front_max_pkt_burst = 32
	local back_max_pkt_burst = 32

	-- These variables are unlikely to need to be changed.
	local tcp_port_bgp = 179
	local num_attempts_kni_link_set = 5
	local max_route_updates = 8
	local scan_interval_sec = 5

	--
	-- End configuration of CPS block.
	--

	local cps_conf = gatekeeper.c.get_cps_conf()
	if cps_conf == nil then
		error("Failed to allocate cps_conf")
	end

	cps_conf.lcore_id = gatekeeper.alloc_an_lcore(numa_table)

	cps_conf.log_level = log_level

	cps_conf.mailbox_max_entries_exp = mailbox_max_entries_exp
	cps_conf.mailbox_mem_cache_size = mailbox_mem_cache_size
	cps_conf.mailbox_burst_size = mailbox_burst_size
	cps_conf.log_ratelimit_interval_ms = log_ratelimit_interval_ms
	cps_conf.log_ratelimit_burst = log_ratelimit_burst
	cps_conf.front_max_pkt_burst = front_max_pkt_burst
	cps_conf.back_max_pkt_burst = back_max_pkt_burst

	cps_conf.tcp_port_bgp = tcp_port_bgp
	cps_conf.num_attempts_kni_link_set = num_attempts_kni_link_set
	cps_conf.max_route_updates = max_route_updates
	cps_conf.scan_interval_sec = scan_interval_sec

	local ret = gatekeeper.c.run_cps(net_conf, gk_conf, gt_conf,
		cps_conf, lls_conf, kni_kmod_path)
	if ret < 0 then
		error("Failed to run cps block")
	end

	return cps_conf
end
