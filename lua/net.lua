local gatekeeperc = require("gatekeeperc")
local ffi = require("ffi")
local ifaces = require("if_map")

local M = {}

function init_iface(iface, name, ports)
	local pci_strs = ffi.new("const char *[" .. #ports .. "]")
	for i, v in ipairs(ports) do
		pci_strs[i - 1] = ifaces[v]
	end
	return gatekeeperc.lua_init_iface(iface, name, pci_strs, #ports)
end

-- Function that sets up the network.
function M.setup_block()

	-- Init the network configuration structure.
	local conf = gatekeeperc.get_net_conf()

	-- Change these parameters to configure the network.
	local front_ports = {"enp131s0f0"}
	local back_ports = {"enp133s0f0"}
	conf.num_rx_queues = 2
	conf.num_tx_queues = 2

	-- Code below this point should not need to be changed.
	local ret = init_iface(conf.front, "front", front_ports)
	if ret < 0 then
		return ret
	end

	ret = init_iface(conf.back, "back", back_ports)
	if ret < 0 then
		goto front
	end

	-- Set up the network.
	ret = gatekeeperc.gatekeeper_init_network(conf)
	if ret < 0 then
		goto back
	end

	do return ret end

::back::
	gatekeeperc.lua_free_iface(conf.back)
::front::
	gatekeeperc.lua_free_iface(conf.front)
	return ret
end

return M
