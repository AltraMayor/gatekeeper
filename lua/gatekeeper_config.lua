-- The gatekeeper module is already loaded, but it only contains
-- C functions statically linked.
-- Unsetting its package.loaded entry allows Lua to load
-- the Lua functions of the module.
package.loaded["gatekeeper"] = nil
require "gatekeeper"

function gatekeeper_init()
	local numa_table = gatekeeper.get_numa_table()

	local netf = require("net")
	local net_conf = netf()

	local llsf = require("lls")
	local lls_conf = llsf(net_conf, numa_table)

	-- Disable the GK and GGU blocks just removing the X below.
	--X[[
	local gkf = require("gk")
	local gk_conf, ggu_lcore = gkf(net_conf, numa_table)

	local gguf = require("ggu")
	local ggu_conf = gguf(net_conf, gk_conf, ggu_lcore)
	--]]

	return 0
end
