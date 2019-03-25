require "gatekeeper/staticlib"
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

	-- Number of attempts to wait for a link to come up.
	--
	-- By waiting for the link to come up before
	-- continuing, it is useful for bonded ports where the
	-- slaves must be activated after starting the bonded
	-- device in order for the link to come up. The slaves
	-- are activated on a timer, so this can take some time.
	-- Once the link comes up, the device is ready for full
	-- speed RX/TX.
	--
	-- In current implementation, it attempts to wait for a
	-- link to come up every 1 second.
	local num_attempts_link_get = 5

	-- The maximum packet lifetime specified by the "Hop Limit" in IPv6.
	-- Decremented by 1 by each node that forwards the packet.
	-- The packet is discarded if Hop Limit is decremented to zero.
	local front_ipv6_default_hop_limits = 255
	local back_ipv6_default_hop_limits = 255

	-- Set the log level for all Gatekeeper activity that is
	-- not associated with a functional block. Only activated
	-- when network starts; for early log entries, set using
	-- the --log-level EAL command line option.
	local log_level = staticlib.c.RTE_LOG_DEBUG

	-- How often the log file should be rotated. The unit is second.
	local rotate_log_interval_sec = 60 * 60 -- 1h

	local front_ports = {"enp133s0f0"}
	-- Each interface should have at most two ip addresses:
	-- 1 IPv4, 1 IPv6.
	local front_ips  = {"10.0.1.1/24", "2001:db8:1::1/48"}
	local front_arp_cache_timeout_sec = 7200
	local front_nd_cache_timeout_sec = 7200
	local front_bonding_mode = staticlib.c.BONDING_MODE_ROUND_ROBIN
	local front_vlan_tag = 0x1234
	local front_vlan_insert = true
	local front_mtu = 1500

	-- XXX #155 They should be analyzed or tested further to find
	-- optimal values. Larger queue size can mitigate bursty behavior,
	-- but can also increase pressure on cache and lead to lower
	-- performance.
	--
	-- Gatekeeper servers are expected to transmit much fewer packets than
	-- they receive, while Grantor servers are expected to transmit about
	-- as many packets as they receive.
	local front_num_rx_desc = gatekeeper_server and 512 or 128
	local front_num_tx_desc = 128

	local back_iface_enabled = gatekeeper_server
	local back_ports = {"enp133s0f1"}
	local back_ips  = {"10.0.2.1/24", "2001:db8:2::1/48"}
	local back_arp_cache_timeout_sec = 7200
	local back_nd_cache_timeout_sec = 7200
	local back_bonding_mode = staticlib.c.BONDING_MODE_ROUND_ROBIN
	local back_vlan_tag = 0x5678
	local back_vlan_insert = true
	local back_mtu = 2048

	-- XXX #155 They should be analyzed or tested further to find
	-- optimal values. Larger queue size can mitigate bursty behavior,
	-- but can also increase pressure on cache and lead to lower
	-- performance.
	local back_num_rx_desc = 128
	local back_num_tx_desc = 128

	--
	-- Code below this point should not need to be changed by operators.
	--

	local net_conf = staticlib.c.get_net_conf()
	net_conf.guarantee_random_entropy = guarantee_random_entropy
	net_conf.num_attempts_link_get = num_attempts_link_get
	net_conf.log_level = log_level
	net_conf.rotate_log_interval_sec = rotate_log_interval_sec

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
		ret = staticlib.init_iface(back_iface, "back",
			back_ports, back_ips, back_vlan_tag)
		if ret < 0 then
			error("Failed to initialize the back interface")
		end
	end

	-- Initialize the network.
	ret = staticlib.c.gatekeeper_init_network(net_conf)
	if ret < 0 then
		error("Failed to initilize the network")
	end

	return net_conf
end
