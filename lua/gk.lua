local gatekeeperc = require("gatekeeperc")

local M = {}

-- Function that sets up the GK functional block.
function M.setup_block(net_conf)

	-- Init the GK configuration structure.
	local gk_conf = gatekeeperc.alloc_gk_conf()
	if gk_conf == nil then return nil end
	
	-- Change these parameters to configure the Gatekeeper.
	gk_conf.lcore_start_id = 1
	gk_conf.lcore_end_id = 2
	gk_conf.flow_ht_size = 1024

	-- Setup the GK functional block.
	local ret = gatekeeperc.run_gk(net_conf, gk_conf)
	if ret < 0 then return nil end

	return gk_conf
end

return M
