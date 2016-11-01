-- TODO Add configuration for other functional blocks.

function gatekeeper_init()
	local net = require("net")
	local net_conf = net.setup_block()
	if net_conf == nil then return -1 end

	local gk = require("gk")
	local gk_conf = gk.setup_block(net_conf)
	if gk_conf == nil then return -1 end

	local ggu = require("ggu")
	local ggu_conf = ggu.setup_block(net_conf, gk_conf)
	if ggu_conf == nil then return -1 end

	return 0
end
