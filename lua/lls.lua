return function (net_conf, numa_table)

	--
	-- Configure the variables below for the LLS block.
	--

	-- These parameters should likely be initially changed.
	local log_level = staticlib.c.RTE_LOG_INFO

	-- XXX #155 These parameters should only be changed for performance reasons.
	local mailbox_max_entries_exp = 7
	local mailbox_mem_cache_size = 0
	local mailbox_burst_size = 32
	local mailbox_max_pkt_sub = 32
	local log_ratelimit_interval_ms = 5000
	local log_ratelimit_burst = 10
	local front_max_pkt_burst = 32
	local back_max_pkt_burst = 32
	local front_icmp_msgs_per_sec = 1000
	local front_icmp_msgs_burst = 50
	local back_icmp_msgs_per_sec = 1000
	local back_icmp_msgs_burst = 50

	-- These variables are unlikely to need to be changed.
	local max_num_cache_records = 1024
	local cache_scan_interval_sec = 10

	--
	-- End configuration of LLS block.
	--

	local lls_conf = staticlib.c.get_lls_conf()
	if lls_conf == nil then
		error("Failed to allocate lls_conf")
	end

	lls_conf.log_level = log_level

	lls_conf.mailbox_max_entries_exp = mailbox_max_entries_exp
	lls_conf.mailbox_mem_cache_size = mailbox_mem_cache_size
	lls_conf.mailbox_burst_size = mailbox_burst_size
	lls_conf.mailbox_max_pkt_sub = mailbox_max_pkt_sub
	lls_conf.log_ratelimit_interval_ms = log_ratelimit_interval_ms
	lls_conf.log_ratelimit_burst = log_ratelimit_burst
	lls_conf.front_max_pkt_burst = front_max_pkt_burst
	lls_conf.back_max_pkt_burst = back_max_pkt_burst
	lls_conf.front_icmp_msgs_per_sec = front_icmp_msgs_per_sec
	lls_conf.front_icmp_msgs_burst = front_icmp_msgs_burst
	lls_conf.back_icmp_msgs_per_sec = back_icmp_msgs_per_sec
	lls_conf.back_icmp_msgs_burst = back_icmp_msgs_burst

	lls_conf.max_num_cache_records = max_num_cache_records
	lls_conf.cache_scan_interval_sec = cache_scan_interval_sec

	lls_conf.lcore_id = staticlib.alloc_an_lcore(numa_table)
	local ret = staticlib.c.run_lls(net_conf, lls_conf)
	if ret < 0 then
		error("Failed to run lls block")
	end

	return lls_conf
end
