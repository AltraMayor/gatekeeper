return function (net_conf, numa_table)

	-- Init the LLS configuration structure.
	local lls_conf = gatekeeper.c.get_lls_conf()
	if lls_conf == nil then
		error("Failed to allocate lls_conf")
	end

	-- Change these parameters to configure the LLS block.
	lls_conf.debug = false
	lls_conf.mailbox_max_entries = 128
	lls_conf.mailbox_mem_cache_size = 64
	lls_conf.mailbox_burst_size = 32

	-- Setup the LLS functional block.
	lls_conf.lcore_id = gatekeeper.alloc_an_lcore(numa_table)
	local ret = gatekeeper.c.run_lls(net_conf, lls_conf)
	if ret < 0 then
		error("Failed to run lls block")
	end

	return lls_conf
end
