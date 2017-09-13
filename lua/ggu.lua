return function (net_conf, gk_conf, lcore)

	-- XXX Sample parameters, need to be tested for better performance.
	local mailbox_max_entries = 128
	local mailbox_mem_cache_size = 64
	local mailbox_burst_size = 32

	-- Init the GGU configuration structure.
	local ggu_conf = gatekeeper.c.alloc_ggu_conf()
	if ggu_conf == nil then
		error("Failed to allocate ggu_conf")
	end

	ggu_conf.lcore_id = lcore
	ggu_conf.ggu_src_port = 0xA0A0
	ggu_conf.ggu_dst_port = 0xB0B0
	ggu_conf.mailbox_max_entries = mailbox_max_entries
	ggu_conf.mailbox_mem_cache_size = mailbox_mem_cache_size
	ggu_conf.mailbox_burst_size = mailbox_burst_size

	-- Setup the GGU functional block.
	local ret = gatekeeper.c.run_ggu(net_conf, gk_conf, ggu_conf)
	if ret < 0 then
		error("Failed to run ggu block")
	end

	return ggu_conf
end
