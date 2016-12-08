local gatekeeperc = require("gatekeeperc")
local ffi = require("ffi")
local ifaces = require("if_map")

local M = {}

function init_iface(iface, name, ports, ips)
	local pci_strs = ffi.new("const char *[" .. #ports .. "]")
	for i, v in ipairs(ports) do
		local pci_addr = ifaces[v]
		if pci_addr == nil then
			error("There is no map for interface " .. v)
		end
		pci_strs[i - 1] = pci_addr
	end

	local ip_strs = ffi.new("const char *[" .. #ips .. "]")
	for i, v in ipairs(ips) do
		ip_strs[i - 1] = v
	end

	return gatekeeperc.lua_init_iface(
		iface, name, pci_strs, #ports, ip_strs, #ips)
end

-- Function that sets up the network.
function M.setup_block()

	-- Init the network configuration structure.
	local conf = gatekeeperc.get_net_conf()

	-- Change these parameters to configure the network.
	local front_ports = {"enp133s0f0"}

	-- Each interface should have at most two ip addresses:
	-- 1 IPv4, 1 IPv6.
	local front_ips  = {"10.0.0.1", "3ffe:2501:200:1fff::7"}

	local front_rx_queues = 2
	local front_tx_queues = 0

	local back_iface_enabled = true
	local back_ports = {"enp133s0f1"}
	local back_ips  = {"10.0.0.2", "3ffe:2501:200:1fff::8"}
	local back_rx_queues = 1
	local back_tx_queues = 2

	-- Code below this point should not need to be changed.
	local front_iface = gatekeeperc.get_if_front(conf)
	front_iface.num_rx_queues = front_rx_queues
	front_iface.num_tx_queues = front_tx_queues
	local ret = init_iface(front_iface, "front", front_ports, front_ips)
	if ret < 0 then
		return nil
	end

	conf.back_iface_enabled = back_iface_enabled
	if back_iface_enabled then
		local back_iface = gatekeeperc.get_if_back(conf)
		back_iface.num_rx_queues = back_rx_queues
		back_iface.num_tx_queues = back_tx_queues
		ret = init_iface(back_iface, "back", back_ports, back_ips)
		if ret < 0 then
			goto front
		end
	end

	-- Set up the network.
	ret = gatekeeperc.gatekeeper_init_network(conf)
	if ret < 0 then
		goto back
	end

	do return conf end

::back::
	if back_iface_enabled then
		gatekeeperc.lua_free_iface(back_iface)
	end
::front::
	gatekeeperc.lua_free_iface(front_iface)
	return nil
end

return M
