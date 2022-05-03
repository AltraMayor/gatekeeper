-- The gatekeeper module is already loaded, but it only contains
-- C functions statically linked.
-- Unsetting its package.loaded entry allows Lua to load
-- the Lua functions of the module.
package.loaded["staticlib"] = nil
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

	local n_fixed_lcores = gatekeeper_server and 4 or 3
	local aux_numa_table =
		staticlib.alloc_lcores_evenly_from_all_numa_nodes(numa_table,
			n_fixed_lcores, 0)
	-- LLS should be the first block initialized, since it should have
	-- queue IDs of 0 so that when ARP filters are not supported ARP
	-- packets are steered to the LLS block by the NIC. This occurs because
	-- many NICs direct non-IP packets to queue 0. This is not necessary
	-- when running Gatekeeper on Amazon, since the ENA distributes non-IP
	-- packets to the first queue configured for RSS.
	local llsf = require("lls")
	local lls_conf = llsf(net_conf, aux_numa_table)

	local gk_conf
	local gt_conf

	if gatekeeper_server == true then
		-- The following expression to set the number of
		-- GK block instances is a good recommendation,
		-- but it may not be optimal for all cases.
		local n_gk_lcores = 2 * staticlib.count_numa_nodes(numa_table)
		if n_gk_lcores <= 0 then
			error("No GK block allocated for Gatekeeper server")
		end

		local n_sol_lcores_per_socket = 1
		local lcores_table =
			staticlib.alloc_lcores_evenly_from_all_numa_nodes(numa_table,
				n_gk_lcores, n_sol_lcores_per_socket)
		local gk_lcores = staticlib.convert_numa_table_to_array(
			staticlib.alloc_lcores_evenly_from_all_numa_nodes(lcores_table,
				n_gk_lcores, 0))
		local sol_lcores = staticlib.convert_numa_table_to_array(lcores_table)
		local gk_sol_map = staticlib.gk_sol_map(gk_lcores, sol_lcores)

		local solf = require("sol")
		local sol_conf = solf(net_conf, sol_lcores)

		local gkf = require("gk")
		gk_conf = gkf(net_conf, lls_conf, sol_conf, gk_lcores, gk_sol_map)

		local gguf = require("ggu")
		local ggu_lcore = staticlib.alloc_an_lcore(aux_numa_table)
		local ggu_conf = gguf(net_conf, gk_conf, ggu_lcore)
	else
		local gtf = require("gt")
		gt_conf = gtf(net_conf, lls_conf, numa_table)
	end

	local cpsf = require("cps")
	local cps_conf = cpsf(net_conf, gk_conf, gt_conf, lls_conf, aux_numa_table)

	local dyf = require("dyn_cfg")
	local dy_conf = dyf(net_conf, gk_conf, gt_conf, aux_numa_table)

	-- A return value of 1 is required for success.
	return 1
end
