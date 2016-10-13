local gatekeeperc = require("gatekeeperc")

local M = {}

-- Function that sets up the GK functional block.
function M.setup_block()

	-- Init the GK configuration structure.
	local conf = gatekeeperc.alloc_gk_conf()
	conf.lcore_start_id = 1
	conf.lcore_end_id = 2
	conf.flow_ht_size = 1024

	-- Setup the GK functional block.
	return gatekeeperc.run_gk(conf)
end

return M
