-- The gatekeeper module is already loaded, but it only contains
-- C functions statically linked.
-- Unsetting its package.loaded entry allows Lua to load
-- the Lua functions of the module.
package.loaded["gatekeeper"] = nil
require "gatekeeper"

-- TODO Add configuration for other functional blocks.

function gatekeeper_init()
	local numa_table = gatekeeper.get_numa_table()

	local net = require("net")
	local net_conf = net.setup_block()
	if net_conf == nil then return -1 end

	local lls = require("lls")
	local lls_conf = lls.setup_block(net_conf, numa_table)
	if lls_conf == nil then return -1 end

	-- Disable the GK and GGU blocks just removing the X below.
	--X[[
	local gk = require("gk")
	local gk_conf, ggu_lcore = gk.setup_block(net_conf, numa_table)
	if gk_conf == nil then return -1 end

	local ggu = require("ggu")
	local ggu_conf = ggu.setup_block(net_conf, gk_conf, ggu_lcore)
	if ggu_conf == nil then return -1 end
	--]]

	return 0
end
