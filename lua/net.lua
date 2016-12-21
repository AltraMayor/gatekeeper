local M = {}

-- Function that sets up the network.
function M.setup_block()

	-- Init the network configuration structure.
	local conf = gatekeeper.c.get_net_conf()

	--
	-- Change these parameters to configure the network.
	--

	local front_ports = {"enp133s0f0"}
	-- Each interface should have at most two ip addresses:
	-- 1 IPv4, 1 IPv6.
	local front_ips  = {"10.0.0.1", "3ffe:2501:200:1fff::7"}
	local front_arp_cache_timeout_sec = 7200

	local back_iface_enabled = true
	local back_ports = {"enp133s0f1"}
	local back_ips  = {"10.0.0.2", "3ffe:2501:200:1fff::8"}
	local back_arp_cache_timeout_sec = 7200

	-- Code below this point should not need to be changed.
	local front_iface = gatekeeper.c.get_if_front(conf)
	front_iface.arp_cache_timeout_sec = front_arp_cache_timeout_sec
	local ret = gatekeeper.init_iface(front_iface, "front",
		front_ports, front_ips)
	if ret < 0 then
		return nil
	end

	conf.back_iface_enabled = back_iface_enabled
	if back_iface_enabled then
		local back_iface = gatekeeper.c.get_if_back(conf)
		back_iface.arp_cache_timeout_sec = back_arp_cache_timeout_sec
		ret = gatekeeper.init_iface(back_iface, "back",
			back_ports, back_ips)
		if ret < 0 then
			goto front
		end
	end

	-- Set up the network.
	ret = gatekeeper.c.gatekeeper_init_network(conf)
	if ret < 0 then
		goto back
	end

	do return conf end

::back::
	if back_iface_enabled then
		gatekeeper.c.lua_free_iface(back_iface)
	end
::front::
	gatekeeper.c.lua_free_iface(front_iface)
	return nil
end

return M
