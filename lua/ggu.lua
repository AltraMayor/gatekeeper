return function (net_conf, gk_conf, lcore)

	--
	-- Configure the variables below for the GGU block.
	--

	-- These parameters should likely be initially changed.
	local log_level = staticlib.c.RTE_LOG_DEBUG

	-- XXX #155 These parameters should only be changed for performance reasons.
	local mailbox_max_entries_exp = 7
	local mailbox_mem_cache_size = 0
	local mailbox_burst_size = 32
	local log_ratelimit_interval_ms = 5000
	local log_ratelimit_burst = 10
	local max_pkt_burst = 32

	-- These variables are unlikely to need to be changed.
	local ggu_src_port = 0xA0A0
	local ggu_dst_port = 0xB0B0

	--
	-- End configuration of GGU block.
	--

	local ggu_conf = staticlib.c.alloc_ggu_conf()
	if ggu_conf == nil then
		error("Failed to allocate ggu_conf")
	end

	ggu_conf.lcore_id = lcore

	ggu_conf.log_level = log_level

	ggu_conf.mailbox_max_entries_exp = mailbox_max_entries_exp
	ggu_conf.mailbox_mem_cache_size = mailbox_mem_cache_size
	ggu_conf.mailbox_burst_size = mailbox_burst_size
	ggu_conf.log_ratelimit_interval_ms = log_ratelimit_interval_ms
	ggu_conf.log_ratelimit_burst = log_ratelimit_burst
	ggu_conf.max_pkt_burst = max_pkt_burst

	ggu_conf.ggu_src_port = ggu_src_port
	ggu_conf.ggu_dst_port = ggu_dst_port

	local ret = staticlib.c.run_ggu(net_conf, gk_conf, ggu_conf)
	if ret < 0 then
		error("Failed to run ggu block")
	end

	return ggu_conf
end
