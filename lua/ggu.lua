local gatekeeperc = require("gatekeeperc")

local M = {}

-- Function that sets up the GGU functional block.
function M.setup_block(net_conf, gk_conf, lcore)

	-- Init the GGU configuration structure.
	local ggu_conf = gatekeeperc.alloc_ggu_conf()
	if ggu_conf == nil then return nil end

	ggu_conf.lcore_id = lcore
	ggu_conf.ggu_src_port = 0xA0A0
	ggu_conf.ggu_dst_port = 0xB0B0

	-- Setup the GGU functional block.
	local ret = gatekeeperc.run_ggu(net_conf, gk_conf, ggu_conf)
	if ret < 0 then
		gatekeeperc.cleanup_ggu(ggu_conf)
		ggu_conf = nil
		return nil
	end

	return ggu_conf
end

return M
