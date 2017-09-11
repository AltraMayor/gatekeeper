require "gatekeeper"
return function (gatekeeper_server)

	--
	-- Change these parameters to configure the network.
	--

	-- In Linux, using /dev/random may require waiting for the result
	-- as it uses the so-called entropy pool, where random data may not be
	-- available at the moment. In contrast, /dev/urandom returns
	-- as many bytes as user requested and thus it is less random than
	-- /dev/random.
	--
	-- The flags parameter in getrandom() will alter the behavior of
	-- the call. In the case where flags == 0, getrandom() will block
	-- until the /dev/urandom pool has been initialized.
	--
	-- Alternatively, the GRND_RANDOM flag bit can be used to switch to the
	-- /dev/random pool, subject to the entropy requirements of that pool.
	--
	-- This parameter is used to decide if flag GRND_RANDOM should be
	-- passed to any call of getradom(2). This is relevant for production
	-- environments to guarantee entropy while machines are booting up.
	local guarantee_random_entropy = 0
	local num_attempts_link_get = 5
	local ipv6_default_hop_limits = 255

	local front_ports = {"enp133s0f0"}
	-- Each interface should have at most two ip addresses:
	-- 1 IPv4, 1 IPv6.
	local front_ips  = {"10.0.0.1/24", "2001:db8::1/32"}
	local front_arp_cache_timeout_sec = 7200
	local front_nd_cache_timeout_sec = 7200
	local front_bonding_mode = gatekeeper.c.BONDING_MODE_ROUND_ROBIN
	local front_vlan_tag = 0x1234
	local front_vlan_insert = true
	local front_mtu = 1500

	local back_iface_enabled = gatekeeper_server
	local back_ports = {"enp133s0f1"}
	local back_ips  = {"10.0.1.1/24", "2002:db8::1/32"}
	local back_arp_cache_timeout_sec = 7200
	local back_nd_cache_timeout_sec = 7200
	local back_bonding_mode = gatekeeper.c.BONDING_MODE_ROUND_ROBIN
	local back_vlan_tag = 0x5678
	local back_vlan_insert = true
	local back_mtu = 2048

	--
	-- Code below this point should not need to be changed by operators.
	--

	local net_conf = gatekeeper.c.get_net_conf()
	net_conf.guarantee_random_entropy = guarantee_random_entropy
	net_conf.num_attempts_link_get = num_attempts_link_get
	net_conf.ipv6_default_hop_limits = ipv6_default_hop_limits

	local front_iface = gatekeeper.c.get_if_front(net_conf)
	front_iface.arp_cache_timeout_sec = front_arp_cache_timeout_sec
	front_iface.nd_cache_timeout_sec = front_nd_cache_timeout_sec
	front_iface.bonding_mode = front_bonding_mode
	front_iface.vlan_insert = front_vlan_insert
	front_iface.mtu = front_mtu
	local ret = gatekeeper.init_iface(front_iface, "front",
		front_ports, front_ips, front_vlan_tag)

	net_conf.back_iface_enabled = back_iface_enabled
	if back_iface_enabled then
		local back_iface = gatekeeper.c.get_if_back(net_conf)
		back_iface.arp_cache_timeout_sec = back_arp_cache_timeout_sec
		back_iface.nd_cache_timeout_sec = back_nd_cache_timeout_sec
		back_iface.bonding_mode = back_bonding_mode
		back_iface.vlan_insert = back_vlan_insert
		back_iface.mtu = back_mtu
		ret = gatekeeper.init_iface(back_iface, "back",
			back_ports, back_ips, back_vlan_tag)
	end

	-- Initialize the network.
	ret = gatekeeper.c.gatekeeper_init_network(net_conf)
	if ret < 0 then
		error("Failed to initilize the network")
	end

	return net_conf
end
