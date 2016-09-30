-- TODO Add configuration for other functional blocks.
local block_names = {
	"net",
	"gk",
}

function gatekeeper_init()
	for _, value in ipairs(block_names) do
		local block = require(value)
		local ret = block.setup_block()
		if ret < 0 then return ret end
	end

	return 0
end
