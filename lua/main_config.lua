-- The gatekeeper module is already loaded, but it only contains
-- C functions statically linked.
-- Unsetting its package.loaded entry allows Lua to load
-- the Lua functions of the module.
package.loaded["gatekeeper/staticlib"] = nil
require "gatekeeper/staticlib"

function gatekeeper_init()

	-- When gatekeeper_server is true,
	-- Gatekeeper will run as a Gatekeeper server.
	-- Otherwise, it will run as a grantor server.
	local gatekeeper_server = true

	-- Set the global log level to one of
	-- RTE_LOG_{EMERG,ALERT,CRIT,ERR,WARNING,NOTICE,INFO,DEBUG}.
	-- All logs equal to or to the left will be output.
	local global_log_level = staticlib.c.RTE_LOG_DEBUG
	staticlib.c.rte_log_set_global_level(global_log_level)

	local netf = require("net")
	local net_conf = netf(gatekeeper_server)

	local numa_table = staticlib.get_numa_table(net_conf)

	-- LLS should be the first block initialized, since it should have
	-- queue IDs of 0 so that when ARP filters are not supported ARP
	-- packets are steered to the LLS block by the NIC. This occurs because
	-- many NICs direct non-IP packets to queue 0. This is not necessary
	-- when running Gatekeeper on Amazon, since the ENA distributes non-IP
	-- packets to the first queue configured for RSS.
	local llsf = require("lls")
	local lls_conf = llsf(net_conf, numa_table)

	local gk_conf
	local gt_conf

	if gatekeeper_server == true then
		-- n_lcores + 2 on same NUMA: for GK-GT Unit and Solicitor.
		local n_lcores = 2
		local gk_lcores =
			staticlib.alloc_lcores_from_same_numa(numa_table,
				n_lcores + 2)
		local sol_lcore = table.remove(gk_lcores)
		local ggu_lcore = table.remove(gk_lcores)

		local solf = require("sol")
		local sol_conf = solf(net_conf, sol_lcore)

		local gkf = require("gk")
		gk_conf = gkf(net_conf, lls_conf, sol_conf, gk_lcores)

		local gguf = require("ggu")
		local ggu_conf = gguf(net_conf, gk_conf, ggu_lcore)
	else
		local gtf = require("gt")
		gt_conf = gtf(net_conf, lls_conf, numa_table)
	end

	-- Allocate CPS after to increase the change that the LLS block is
	-- allocated in the same NUMA node as the GK/GT/GK-GT-unit blocks.
	local cpsf = require("cps")
	local cps_conf = cpsf(net_conf, gk_conf, gt_conf, lls_conf, numa_table)

	local dyf = require("dyn_cfg")
	local dy_conf = dyf(net_conf, gk_conf, gt_conf, numa_table)

	return 0
end
