return function (net_conf, lcore)

	-- Init the Solicitor configuration structure.
	local sol_conf = gatekeeper.c.alloc_sol_conf()
	if sol_conf == nil then
		error("Failed to allocate sol_conf")
	end

	sol_conf.lcore_id = lcore
	sol_conf.pri_req_max_len = 1024
	sol_conf.req_bw_rate = 0.05
	-- These values should be tested to find optimal values.
	sol_conf.enq_burst_size = 32
	sol_conf.deq_burst_size = 32
	sol_conf.mailbox_mem_cache_size = 0

	-- Token bucket rate approximation error.
	sol_conf.tb_rate_approx_err = 1e-7

	-- Only used when the NIC does not provide a
	-- guaranteed bandwidth, such as Amazon ENA.
	-- Otherwise, should be kept as 0.
	sol_conf.req_channel_bw_mbps = 0.0

	-- Setup the sol functional block.
	local ret = gatekeeper.c.run_sol(net_conf, sol_conf)
	if ret < 0 then
		error("Failed to run sol block")
	end

	return sol_conf
end
