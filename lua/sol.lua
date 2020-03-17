return function (net_conf, sol_lcores)

	--
	-- Configure the variables below for the SOL block.
	--

	-- These parameters should likely be initially changed.
	local log_level = staticlib.c.RTE_LOG_DEBUG

	-- XXX #155 These parameters should only be changed for performance reasons.
	local log_ratelimit_interval_ms = 5000
	local log_ratelimit_burst = 10
	local pri_req_max_len = 512
	local req_bw_rate = 0.05
	local enq_burst_size = 32
	local deq_burst_size = 32

	-- These variables are unlikely to need to be changed.
	local tb_rate_approx_err = 1e-7
	local req_channel_bw_mbps = 0.0

	--
	-- End configuration of SOL block.
	--

	local sol_conf = staticlib.c.alloc_sol_conf()
	if sol_conf == nil then
		error("Failed to allocate sol_conf")
	end

	staticlib.sol_assign_lcores(sol_conf, sol_lcores)

	sol_conf.log_level = log_level

	sol_conf.log_ratelimit_interval_ms = log_ratelimit_interval_ms
	sol_conf.log_ratelimit_burst = log_ratelimit_burst
	sol_conf.pri_req_max_len = pri_req_max_len
	sol_conf.req_bw_rate = req_bw_rate
	sol_conf.enq_burst_size = enq_burst_size
	sol_conf.deq_burst_size = deq_burst_size

	sol_conf.tb_rate_approx_err = tb_rate_approx_err
	sol_conf.req_channel_bw_mbps = req_channel_bw_mbps

	local ret = staticlib.c.run_sol(net_conf, sol_conf)
	if ret < 0 then
		error("Failed to run sol block")
	end

	return sol_conf
end
