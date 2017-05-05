-- The gatekeeper module is already loaded, but it only contains
-- C functions statically linked.
-- Unsetting its package.loaded entry allows Lua to load
-- the Lua functions of the module.
package.loaded["gatekeeper"] = nil
require "gatekeeper"

function gatekeeper_init()

	-- When gatekeeper_server is true,
	-- Gatekeeper will run as a Gatekeeper server.
	-- Otherwise, it will run as a grantor server.
	local gatekeeper_server = true

	local numa_table = gatekeeper.get_numa_table()

	local netf = require("net")
	local net_conf = netf(gatekeeper_server)

	local llsf = require("lls")
	local lls_conf = llsf(net_conf, numa_table)

	if gatekeeper_server == true then
		-- n_lcores + 2 on same NUMA: for GK-GT Unit and Solicitor.
		local n_lcores = 2
		local gk_lcores =
			gatekeeper.alloc_lcores_from_same_numa(numa_table,
				n_lcores + 2)
		local sol_lcore = table.remove(gk_lcores)
		local ggu_lcore = table.remove(gk_lcores)

		local solf = require("sol")
		local sol_conf = solf(net_conf, sol_lcore)

		local gkf = require("gk")
		local gk_conf = gkf(net_conf, sol_conf, gk_lcores)

		local gguf = require("ggu")
		local ggu_conf = gguf(net_conf, gk_conf, ggu_lcore)
	else
		local gtf = require("gt")
		local gt_conf = gtf(net_conf, numa_table)
	end

	-- Allocate CPS after to increase the change that the LLS block is
	-- allocated in the same NUMA node as the GK/GT/GK-GT-unit blocks.
	local cpsf = require("cps")
	local cps_conf = cpsf(net_conf, lls_conf, numa_table)

	local dyf = require("dyn_cfg")
	local dy_conf = dyf(numa_table)

	return 0
end
