-- TODO Add configuration for other functional blocks.
local block_names = {
	"gk",
}

function gatekeeper_init()
	local net = require("net")
	local net_conf = net.setup_block()
	if net_conf == nil then return -1 end

	for _, value in ipairs(block_names) do
		local block = require(value)
		local ret = block.setup_block(net_conf)
		if ret < 0 then return ret end
	end

	return 0
end
