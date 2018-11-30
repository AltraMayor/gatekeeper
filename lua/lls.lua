return function (net_conf, numa_table)

	-- Init the LLS configuration structure.
	local lls_conf = gatekeeper.c.get_lls_conf()
	if lls_conf == nil then
		error("Failed to allocate lls_conf")
	end

	-- Change these parameters to configure the LLS block.
	lls_conf.debug = false

	-- XXX Sample parameters, need to be tested for better performance.
	lls_conf.mailbox_max_entries_exp = 7
	lls_conf.mailbox_burst_size = 32

	-- The maximum number of packets to retrieve/transmit.
	lls_conf.front_max_pkt_burst = 32
	lls_conf.back_max_pkt_burst = 32

	-- The maximum number of ARP or ND packets submitted by GK or GT.
	lls_conf.mailbox_max_pkt_burst = 32

	-- Setup the LLS functional block.
	lls_conf.lcore_id = gatekeeper.alloc_an_lcore(numa_table)
	local ret = gatekeeper.c.run_lls(net_conf, lls_conf)
	if ret < 0 then
		error("Failed to run lls block")
	end

	return lls_conf
end
