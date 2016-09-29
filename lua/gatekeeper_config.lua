local ffi = require("ffi")
local gatekeeperc = require("gatekeeperc")

-- TODO Add configuration for other functional blocks.
local block_names = {
	"net",
	"gk",
}

function gatekeeper_init()
	local ret = 0

	for key, value in ipairs(block_names) do
		block = require(value)
        	ret = block.setup_block()
		if ret < 0 then return ret end
	end

	return ret
end
