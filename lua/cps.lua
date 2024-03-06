return function (net_conf, gk_conf, gt_conf, lls_conf, numa_table)

	--
	-- Configure the variables below for the CPS block.
	--

	-- These parameters should likely be initially changed.
	local log_level = staticlib.c.RTE_LOG_DEBUG

	-- XXX #155 These parameters should only be changed for performance reasons.
	local mailbox_max_entries_exp = 7
	local mailbox_mem_cache_size = 0
	local mailbox_burst_size = 32
	local log_ratelimit_interval_ms = 5000
	local log_ratelimit_burst = 10
	local front_max_pkt_burst = 32
	local back_max_pkt_burst = 32
	local arp_max_entries_exp = 10
	local nd_max_entries_exp = 10

	-- These variables are unlikely to need to be changed.
	local kni_queue_size = 1024
	local max_rt_update_pkts = 8
	local scan_interval_sec = 5

	--
	-- End configuration of CPS block.
	--

	local cps_conf = staticlib.c.get_cps_conf()
	if cps_conf == nil then
		error("Failed to allocate cps_conf")
	end

	cps_conf.lcore_id = staticlib.alloc_an_lcore(numa_table)

	cps_conf.log_level = log_level

	cps_conf.mailbox_max_entries_exp = mailbox_max_entries_exp
	cps_conf.mailbox_mem_cache_size = mailbox_mem_cache_size
	cps_conf.mailbox_burst_size = mailbox_burst_size
	cps_conf.log_ratelimit_interval_ms = log_ratelimit_interval_ms
	cps_conf.log_ratelimit_burst = log_ratelimit_burst
	cps_conf.front_max_pkt_burst = front_max_pkt_burst
	cps_conf.back_max_pkt_burst = back_max_pkt_burst
	cps_conf.kni_queue_size = kni_queue_size
	cps_conf.max_rt_update_pkts = max_rt_update_pkts
	cps_conf.scan_interval_sec = scan_interval_sec

	-- Netlink port ID to receive updates and scans from routing daemon.
	cps_conf.nl_pid = 0x6A7E

	cps_conf.arp_max_entries_exp = arp_max_entries_exp
	cps_conf.nd_max_entries_exp = nd_max_entries_exp

	local ret = staticlib.c.run_cps(net_conf, gk_conf, gt_conf,
		cps_conf, lls_conf)
	if ret < 0 then
		error("Failed to run cps block")
	end

	return cps_conf
end
