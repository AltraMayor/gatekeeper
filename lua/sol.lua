return function (net_conf, lcore)

	-- Init the Solicitor configuration structure.
	local sol_conf = gatekeeper.c.alloc_sol_conf()
	if sol_conf == nil then
		error("Failed to allocate sol_conf")
	end

	sol_conf.lcore_id = lcore
	sol_conf.pri_req_max_len = 1024
	sol_conf.req_bw_rate = 0.05
	-- These values should likely be set in accordance with
	-- gatekeeper_max_pkt_burst in gatekeeper_config and
	-- should be tested to find optimal values.
	sol_conf.enq_burst_size = 32
	sol_conf.deq_burst_size = 32

	-- Setup the sol functional block.
	local ret = gatekeeper.c.run_sol(net_conf, sol_conf)
	if ret < 0 then
		error("Failed to run sol block")
	end

	return sol_conf
end
