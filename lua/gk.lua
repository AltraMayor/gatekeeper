return function (net_conf, lls_conf, sol_conf, gk_lcores)

	-- Init the GK configuration structure.
	local gk_conf = gatekeeper.c.alloc_gk_conf()
	if gk_conf == nil then
		error("Failed to allocate gk_conf")
	end
	
	-- Change these parameters to configure the Gatekeeper.
	gk_conf.flow_ht_size = 1024

	gatekeeper.gk_assign_lcores(gk_conf, gk_lcores)

	gk_conf.max_num_ipv4_rules = 1024
	gk_conf.num_ipv4_tbl8s = 256
	gk_conf.max_num_ipv6_rules = 1024
	gk_conf.num_ipv6_tbl8s = 65536

	-- 48h.
	gatekeeper.c.set_gk_request_timeout(48 * 60 * 60, gk_conf)

	gk_conf.max_num_ipv6_neighbors = 65536
	gk_conf.gk_max_num_ipv4_fib_entries = 256
	gk_conf.gk_max_num_ipv6_fib_entries = 65536

	-- Scan the whole flow table in 10 minutes.
	gk_conf.flow_table_full_scan_ms = 10 * 60 * 1000

	-- The maximum number of packets to retrieve/transmit.
	local gk_max_pkt_burst_front = 32
	local gk_max_pkt_burst_back = 32

	--
	-- Code below this point should not need to be changed.
	--

	if not gatekeeper.c.ipv4_configured(net_conf) then
		gk_conf.gk_max_num_ipv4_fib_entries = 0
	end

	if not gatekeeper.c.ipv6_configured(net_conf) then
		gk_conf.gk_max_num_ipv6_fib_entries = 0
	end

	gk_conf.front_max_pkt_burst =
		gatekeeper.get_front_burst_config(
			gk_max_pkt_burst_front, net_conf)
	gk_conf.back_max_pkt_burst =
		gatekeeper.get_back_burst_config(
			gk_max_pkt_burst_back, net_conf)
	-- The maximum number of ARP or ND packets in LLS submitted by
	-- GK or GT. The code below makes sure that the parameter should
	-- be at least the same with the maximum configured value of GK.
	lls_conf.mailbox_max_pkt_burst =
		math.max(lls_conf.mailbox_max_pkt_burst,
		gk_conf.front_max_pkt_burst, gk_conf.back_max_pkt_burst)

	-- Setup the GK functional block.
	local ret = gatekeeper.c.run_gk(net_conf, gk_conf, sol_conf)
	if ret < 0 then
		error("Failed to run gk block(s)")
	end

	return gk_conf
end
