return function (net_conf, lls_conf, sol_conf, gk_lcores)

	--
	-- Configure the variables below for the GK block.
	--

	-- These parameters should likely be initially changed.
	local log_level = staticlib.c.RTE_LOG_DEBUG
	local bpf_base_directory = "./lua/bpf"
	local bpf_programs = {
		[0] = "granted.bpf",
		[1] = "declined.bpf",
		[2] = "grantedv2.bpf",
		[3] = "web.bpf",
	}

	-- XXX #155 These parameters should only be changed for performance reasons.
	local mailbox_max_entries_exp = 14
	local mailbox_mem_cache_size = 0
	local mailbox_burst_size = 32
	local log_ratelimit_interval_ms = 5000
	local log_ratelimit_burst = 10
	local max_pkt_burst_front = 32
	local max_pkt_burst_back = 32

	local flow_ht_size = 1024
	local flow_table_scan_iter = 1000

	local max_num_ipv4_rules = 1024
	local num_ipv4_tbl8s = 256
	local max_num_ipv6_rules = 1024
	local num_ipv6_tbl8s = 65536
	local max_num_ipv6_neighbors = 65536
	local max_num_ipv4_fib_entries = 256
	local max_num_ipv6_fib_entries = 65536

	local basic_measurement_logging_ms = 60 * 1000 -- (1 minute)

	local front_icmp_msgs_per_sec = 1000
	local front_icmp_msgs_burst = 50
	local back_icmp_msgs_per_sec = 1000
	local back_icmp_msgs_burst = 50

	-- These variables are unlikely to need to be changed.
	local bpf_enable_jit = true

	--
	-- End configuration of GK block.
	--

	local gk_conf = staticlib.c.alloc_gk_conf()
	if gk_conf == nil then
		error("Failed to allocate gk_conf")
	end
	
	local num_lcores = #gk_lcores
	staticlib.gk_assign_lcores(gk_conf, gk_lcores)

	gk_conf.log_level = log_level

	gk_conf.mailbox_max_entries_exp = mailbox_max_entries_exp
	gk_conf.mailbox_mem_cache_size = mailbox_mem_cache_size
	gk_conf.mailbox_burst_size = mailbox_burst_size
	gk_conf.log_ratelimit_interval_ms = log_ratelimit_interval_ms
	gk_conf.log_ratelimit_burst = log_ratelimit_burst

	gk_conf.flow_ht_size = flow_ht_size
	gk_conf.max_num_ipv4_rules = max_num_ipv4_rules
	gk_conf.num_ipv4_tbl8s = num_ipv4_tbl8s
	gk_conf.max_num_ipv6_rules = max_num_ipv6_rules
	gk_conf.num_ipv6_tbl8s = num_ipv6_tbl8s
	gk_conf.max_num_ipv6_neighbors = max_num_ipv6_neighbors

	if staticlib.c.ipv4_configured(net_conf) then
		gk_conf.max_num_ipv4_fib_entries = max_num_ipv4_fib_entries
	else
		gk_conf.max_num_ipv4_fib_entries = 0
	end

	if staticlib.c.ipv6_configured(net_conf) then
		gk_conf.max_num_ipv6_fib_entries = max_num_ipv6_fib_entries
	else
		gk_conf.max_num_ipv6_fib_entries = 0
	end

	gk_conf.flow_table_scan_iter = flow_table_scan_iter
	gk_conf.basic_measurement_logging_ms = basic_measurement_logging_ms

	gk_conf.front_icmp_msgs_per_sec = math.floor(front_icmp_msgs_per_sec /
		num_lcores + 0.5)
	gk_conf.front_icmp_msgs_burst = front_icmp_msgs_burst
	gk_conf.back_icmp_msgs_per_sec = math.floor(back_icmp_msgs_per_sec /
		num_lcores + 0.5)
	gk_conf.back_icmp_msgs_burst = back_icmp_msgs_burst

	gk_conf.front_max_pkt_burst =
		staticlib.get_front_burst_config(max_pkt_burst_front, net_conf)
	gk_conf.back_max_pkt_burst =
		staticlib.get_back_burst_config(max_pkt_burst_back, net_conf)

	-- The maximum number of ARP or ND packets in LLS submitted by
	-- GK or GT. The code below makes sure that the parameter should
	-- be at least the same with the maximum configured value of GK.
	lls_conf.mailbox_max_pkt_sub =
		math.max(lls_conf.mailbox_max_pkt_sub,
		gk_conf.front_max_pkt_burst, gk_conf.back_max_pkt_burst)

	-- Load BPF programs.
	for program_index, program_name in pairs(bpf_programs) do
		local filename = bpf_base_directory .. "/" .. program_name
		local ret = staticlib.c.gk_load_bpf_flow_handler(gk_conf,
			program_index, filename, bpf_enable_jit)
		if ret < 0 then
			error("Failed to load BPF program: " .. filename)
		end
	end

	local ret = staticlib.c.run_gk(net_conf, gk_conf, sol_conf)
	if ret < 0 then
		error("Failed to run gk block(s)")
	end

	return gk_conf
end
