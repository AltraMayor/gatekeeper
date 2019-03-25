return function (net_conf, lls_conf, sol_conf, gk_lcores)

	-- XXX #155 Sample parameters, need to be tested for better performance.
	local mailbox_max_entries_exp = 7
	local mailbox_mem_cache_size = 0
	local mailbox_burst_size = 32

	-- Log ratelimit interval and burst size.
	local log_ratelimit_interval_ms = 5000
	local log_ratelimit_burst = 10

	-- Init the GK configuration structure.
	local gk_conf = staticlib.c.alloc_gk_conf()
	if gk_conf == nil then
		error("Failed to allocate gk_conf")
	end
	
	local num_lcores = #gk_lcores

	-- Change these parameters to configure the Gatekeeper.
	gk_conf.flow_ht_size = 1024

	-- Log level for GK.
	gk_conf.log_level = staticlib.c.RTE_LOG_DEBUG

	staticlib.gk_assign_lcores(gk_conf, gk_lcores)

	gk_conf.max_num_ipv4_rules = 1024
	gk_conf.num_ipv4_tbl8s = 256
	gk_conf.max_num_ipv6_rules = 1024
	gk_conf.num_ipv6_tbl8s = 65536

	-- 48h.
	staticlib.c.set_gk_request_timeout(48 * 60 * 60, gk_conf)

	gk_conf.max_num_ipv6_neighbors = 65536
	gk_conf.gk_max_num_ipv4_fib_entries = 256
	gk_conf.gk_max_num_ipv6_fib_entries = 65536

	-- Scan the whole flow table in 10 minutes.
	gk_conf.flow_table_full_scan_ms = 10 * 60 * 1000

	-- Logging the basic measurements in a minute.
	gk_conf.basic_measurement_logging_ms = 60 * 1000

	-- The maximum number of packets to retrieve/transmit.
	local gk_max_pkt_burst_front = 32
	local gk_max_pkt_burst_back = 32

	-- The rate and burst size of the icmp messages.
	local front_icmp_msgs_per_sec = 1000
	local front_icmp_msgs_burst = 50
	local back_icmp_msgs_per_sec = 1000
	local back_icmp_msgs_burst = 50

	--
	-- Code below this point should not need to be changed.
	--

	gk_conf.mailbox_max_entries_exp = mailbox_max_entries_exp
	gk_conf.mailbox_mem_cache_size = mailbox_mem_cache_size
	gk_conf.mailbox_burst_size = mailbox_burst_size

	gk_conf.log_ratelimit_interval_ms = log_ratelimit_interval_ms
	gk_conf.log_ratelimit_burst = log_ratelimit_burst

	if not staticlib.c.ipv4_configured(net_conf) then
		gk_conf.gk_max_num_ipv4_fib_entries = 0
	end

	if not staticlib.c.ipv6_configured(net_conf) then
		gk_conf.gk_max_num_ipv6_fib_entries = 0
	end

	gk_conf.front_max_pkt_burst =
		staticlib.get_front_burst_config(
			gk_max_pkt_burst_front, net_conf)
	gk_conf.back_max_pkt_burst =
		staticlib.get_back_burst_config(
			gk_max_pkt_burst_back, net_conf)

	gk_conf.front_icmp_msgs_per_sec = math.floor(front_icmp_msgs_per_sec /
		num_lcores + 0.5)
	gk_conf.front_icmp_msgs_burst = front_icmp_msgs_burst
	gk_conf.back_icmp_msgs_per_sec = math.floor(back_icmp_msgs_per_sec /
		num_lcores + 0.5)
	gk_conf.back_icmp_msgs_burst = back_icmp_msgs_burst

	-- The maximum number of ARP or ND packets in LLS submitted by
	-- GK or GT. The code below makes sure that the parameter should
	-- be at least the same with the maximum configured value of GK.
	lls_conf.mailbox_max_pkt_burst =
		math.max(lls_conf.mailbox_max_pkt_burst,
		gk_conf.front_max_pkt_burst, gk_conf.back_max_pkt_burst)

	-- Setup the GK functional block.
	local ret = staticlib.c.run_gk(net_conf, gk_conf, sol_conf)
	if ret < 0 then
		error("Failed to run gk block(s)")
	end

	return gk_conf
end
