require "gatekeeper/staticlib"
return function (gatekeeper_server)

	--
	-- Change these parameters to configure the network.
	--

	-- These parameters should likely be initially changed.
	local log_level = staticlib.c.RTE_LOG_DEBUG
	local user --= "gatekeeper"

	local front_ports = {"enp133s0f0"}
	local front_ips  = {"10.0.1.1/24", "2001:db8:1::1/48"}
	local front_bonding_mode = staticlib.c.BONDING_MODE_ROUND_ROBIN
	local front_vlan_tag = 0x123
	local front_vlan_insert = true
	local front_mtu = 1500
	local front_ipv4_hw_udp_cksum = true
	local front_ipv6_hw_udp_cksum = true

	local back_ports = {"enp133s0f1"}
	local back_ips  = {"10.0.2.1/24", "2001:db8:2::1/48"}
	local back_bonding_mode = staticlib.c.BONDING_MODE_ROUND_ROBIN
	local back_vlan_tag = 0x456
	local back_vlan_insert = true
	local back_mtu = 2048
	local back_ipv4_hw_udp_cksum = true
	local back_ipv6_hw_udp_cksum = true

	-- XXX #155 These parameters should only be changed for performance reasons.
	local front_arp_cache_timeout_sec = 7200 -- (2 hours)
	local front_nd_cache_timeout_sec = 7200  -- (2 hours)
	local front_num_rx_desc = gatekeeper_server and 512 or 128
	local front_num_tx_desc = 128

	local back_arp_cache_timeout_sec = 7200  -- (2 hours)
	local back_nd_cache_timeout_sec = 7200   -- (2 hours)
	local back_num_rx_desc = 128
	local back_num_tx_desc = 128

	-- These variables are unlikely to need to be changed.
	local guarantee_random_entropy = 0
	local num_attempts_link_get = 5
	local front_ipv6_default_hop_limits = 255
	local back_ipv6_default_hop_limits = 255
	local rotate_log_interval_sec = 60 * 60  -- (1 hour)
	local front_ipv4_hw_cksum = true
	local back_ipv4_hw_cksum = true

	--
	-- End configuration of the network.
	--

	local net_conf = staticlib.c.get_net_conf()
	net_conf.guarantee_random_entropy = guarantee_random_entropy
	net_conf.num_attempts_link_get = num_attempts_link_get
	net_conf.log_level = log_level
	net_conf.rotate_log_interval_sec = rotate_log_interval_sec

	local back_iface_enabled = gatekeeper_server

	if back_iface_enabled then
		staticlib.check_ifaces(front_ports, back_ports)
	end

	local front_iface = staticlib.c.get_if_front(net_conf)
	front_iface.arp_cache_timeout_sec = front_arp_cache_timeout_sec
	front_iface.nd_cache_timeout_sec = front_nd_cache_timeout_sec
	front_iface.bonding_mode = front_bonding_mode
	front_iface.vlan_insert = front_vlan_insert
	front_iface.mtu = front_mtu
	front_iface.ipv6_default_hop_limits = front_ipv6_default_hop_limits
	front_iface.num_rx_desc = front_num_rx_desc
	front_iface.num_tx_desc = front_num_tx_desc
	front_iface.ipv4_hw_udp_cksum = front_ipv4_hw_udp_cksum
	front_iface.ipv6_hw_udp_cksum = front_ipv6_hw_udp_cksum
	front_iface.ipv4_hw_cksum = front_ipv4_hw_cksum
	local ret = staticlib.init_iface(front_iface, "front",
		front_ports, front_ips, front_vlan_tag)
	if ret < 0 then
		error("Failed to initialize the front interface")
	end

	net_conf.back_iface_enabled = back_iface_enabled
	if back_iface_enabled then
		local back_iface = staticlib.c.get_if_back(net_conf)
		back_iface.arp_cache_timeout_sec = back_arp_cache_timeout_sec
		back_iface.nd_cache_timeout_sec = back_nd_cache_timeout_sec
		back_iface.bonding_mode = back_bonding_mode
		back_iface.vlan_insert = back_vlan_insert
		back_iface.mtu = back_mtu
		back_iface.ipv6_default_hop_limits =
			back_ipv6_default_hop_limits
		back_iface.num_rx_desc = back_num_rx_desc
		back_iface.num_tx_desc = back_num_tx_desc
		back_iface.ipv4_hw_udp_cksum = back_ipv4_hw_udp_cksum
		back_iface.ipv6_hw_udp_cksum = back_ipv6_hw_udp_cksum
		back_iface.ipv4_hw_cksum = back_ipv4_hw_cksum
		ret = staticlib.init_iface(back_iface, "back",
			back_ports, back_ips, back_vlan_tag)
		if ret < 0 then
			error("Failed to initialize the back interface")
		end
	end

	-- Setup the user that Gatekeeper runs on after it boots.
	if user ~= nil then
		ret = staticlib.c.gatekeeper_setup_user(net_conf, user)
		if ret < 0 then
			error("Failed to setup the user")
		end
	end

	-- Initialize the network.
	ret = staticlib.c.gatekeeper_init_network(net_conf)
	if ret < 0 then
		error("Failed to initilize the network")
	end

	return net_conf
end
