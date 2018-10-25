return function (net_conf, gk_conf, gt_conf, lls_conf, numa_table)
	--
	-- These parameters should not need to be changed after initial setup.
	--
	local kni_kmod_path =
		"/home/cody/gatekeeper/dependencies/dpdk/build/kmod/rte_kni.ko"
	local tcp_port_bgp = 179

	-- Init the CPS configuration structure.
	local cps_conf = gatekeeper.c.get_cps_conf()
	if cps_conf == nil then
		error("Failed to allocate cps_conf")
	end

	-- Setup the CPS functional block.
	cps_conf.lcore_id = gatekeeper.alloc_an_lcore(numa_table)
	cps_conf.tcp_port_bgp = tcp_port_bgp
	cps_conf.debug = false

	-- The maximum number of packets to retrieve/transmit.
	cps_conf.front_max_pkt_burst = 32
	cps_conf.back_max_pkt_burst = 32

	-- Number of times to attempt bring a KNI interface up or down.
	cps_conf.num_attempts_kni_link_set = 5

	-- Maximum number of updates for LPM table to serve at once.
	cps_conf.max_cps_route_updates = 8

	local ret = gatekeeper.c.run_cps(net_conf, gk_conf, gt_conf,
		cps_conf, lls_conf, kni_kmod_path)
	if ret < 0 then
		error("Failed to run cps block")
	end

	return cps_conf
end
