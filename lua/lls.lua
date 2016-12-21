return function (net_conf, numa_table)

	-- Init the LLS configuration structure.
	local lls_conf = gatekeeper.c.get_lls_conf()
	if lls_conf == nil then return nil end

	-- Change these parameters to configure the LLS block.
	lls_conf.debug = false

	-- Setup the LLS functional block.
	lls_conf.lcore_id = gatekeeper.alloc_an_lcore(numa_table)
	local ret = gatekeeper.c.run_lls(net_conf, lls_conf)
	if ret < 0 then return nil end

	return lls_conf
end
