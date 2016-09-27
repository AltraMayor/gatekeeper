local ffi = require("ffi")
local gatekeeperc = require("gatekeeperc")

-- TODO Add configuration for other functional blocks.
local block_names = {}

function gatekeeper_init()
	local ret = 0

	for key, value in ipairs(block_names) do
		block = require(value)
		-- TODO Set up the funcitonal block.
	end

	return ret
end
