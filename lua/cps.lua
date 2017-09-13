return function (net_conf, gk_conf, gt_conf, lls_conf, numa_table)
	--
	-- These parameters should not need to be changed after initial setup.
	--
	local kni_kmod_path =
		"/home/cody/gatekeeper/dependencies/dpdk/build/kmod/rte_kni.ko"
	local tcp_port_bgp = 179

	-- XXX Sample parameters, need to be tested for better performance.
	local mailbox_max_entries = 128
	local mailbox_mem_cache_size = 64
	local mailbox_burst_size = 32

	-- Init the CPS configuration structure.
	local cps_conf = gatekeeper.c.get_cps_conf()
	if cps_conf == nil then
		error("Failed to allocate cps_conf")
	end

	-- Setup the CPS functional block.
	cps_conf.lcore_id = gatekeeper.alloc_an_lcore(numa_table)
	cps_conf.tcp_port_bgp = tcp_port_bgp
	cps_conf.mailbox_max_entries = mailbox_max_entries
	cps_conf.mailbox_mem_cache_size = mailbox_mem_cache_size
	cps_conf.mailbox_burst_size = mailbox_burst_size
	cps_conf.debug = false
	cps_conf.num_attempts_kni_link_set = 5
	cps_conf.max_cps_route_updates = 8
	cps_conf.cps_scan_interval_sec = 5

	local ret = gatekeeper.c.run_cps(net_conf, gk_conf, gt_conf,
		cps_conf, lls_conf, kni_kmod_path)
	if ret < 0 then
		error("Failed to run cps block")
	end

	return cps_conf
end
