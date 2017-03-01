return function (net_conf, numa_table)
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

	local ret = gatekeeper.c.run_cps(net_conf, cps_conf, kni_kmod_path)
	if ret < 0 then
		error("Failed to run cps block")
	end

	return cps_conf
end
