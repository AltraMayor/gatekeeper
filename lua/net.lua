return function ()
	--
	-- Change these parameters to configure the network.
	--

	local front_ports = {"enp133s0f0"}
	-- Each interface should have at most two ip addresses:
	-- 1 IPv4, 1 IPv6.
	local front_ips  = {"10.0.0.1/24", "3ffe:2501:200:1fff::7/48"}
	local front_arp_cache_timeout_sec = 7200

	local back_iface_enabled = true
	local back_ports = {"enp133s0f1"}
	local back_ips  = {"10.0.0.2/24", "3ffe:2501:200:1fff::8/48"}
	local back_arp_cache_timeout_sec = 7200

	--
	-- Code below this point should not need to be changed.
	--

	local net_conf = gatekeeper.c.get_net_conf()
	local front_iface = gatekeeper.c.get_if_front(net_conf)
	front_iface.arp_cache_timeout_sec = front_arp_cache_timeout_sec
	local ret = gatekeeper.init_iface(front_iface, "front",
		front_ports, front_ips)

	net_conf.back_iface_enabled = back_iface_enabled
	if back_iface_enabled then
		local back_iface = gatekeeper.c.get_if_back(net_conf)
		back_iface.arp_cache_timeout_sec = back_arp_cache_timeout_sec
		ret = gatekeeper.init_iface(back_iface, "back",
			back_ports, back_ips)
	end

	-- Initialize the network.
	ret = gatekeeper.c.gatekeeper_init_network(net_conf)
	if ret < 0 then
		error("Failed to initilize the network")
	end

	return net_conf
end
