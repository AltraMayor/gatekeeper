-- The gatekeeper module is already loaded, but it only contains
-- C functions statically linked.
-- Unsetting its package.loaded entry allows Lua to load
-- the Lua functions of the module.
package.loaded["gatekeeper"] = nil
require "gatekeeper"

local function gatekeeper_config_init()
	-- Init the gatekeeper configuration structure.
	local gatekeeper_conf = gatekeeper.c.get_gatekeeper_conf()
	if gatekeeper_conf == nil then
		error("Failed to allocate gatekeeper_conf")
	end

	-- XXX Sample parameters for test only.
	gatekeeper_conf.gatekeeper_max_pkt_burst = 32
	gatekeeper_conf.gatekeeper_max_ports = 4
	gatekeeper_conf.gatekeeper_max_queues = 8

	-- XXX They should be analyzed or tested further to find optimal values.
	-- Larger queue size can mitigate bursty behavior, but can also increase
	-- pressure on cache and lead to lower performance.
	gatekeeper_conf.gatekeeper_num_rx_desc = 128
	gatekeeper_conf.gatekeeper_num_tx_desc = 512

	-- XXX Sample parameter for the number of elements in the mbuf pool.
	-- This should be analyzed or tested further to find optimal value.
	--
	-- The optimum size (in terms of memory usage) for a mempool is when
	-- it is a power of two minus one.
	--
	-- Need to provision enough memory for the worst case,
	-- since each queue needs at least
	-- gatekeeper_num_rx_desc + gatekeeper_num_tx_desc +
	-- gatekeeper_max_pkt_burst descriptors. i.e.,
	-- GATEKEEPER_DESC_PER_QUEUE = (gatekeeper_num_rx_desc +
	-- gatekeeper_num_tx_desc + gatekeeper_max_pkt_burst (let's say 32))
	-- = 672.
	--
	-- So, the pool size should be at least the maximum number of queues *
	-- number of descriptors per queue, i.e.,
	-- (gatekeeper_max_ports * gatekeeper_max_queues *
	-- GATEKEEPER_DESC_PER_QUEUE - 1) = 5376.
	gatekeeper_conf.gatekeeper_mbuf_size = 8191

	-- XXX Sample parameter for the size of the per-core object cache,
	-- i.e., number of struct rte_mbuf elements in the per-core object cache.
	-- this should be analyzed or tested further to find optimal value.
	--
	-- Each core deals with at most gatekeeper_max_ports queues,
	-- so the cache size should be at least
	-- (number of ports * number of descriptors per queue), i.e.,
	-- (gatekeeper_max_ports * GATEKEEPER_DESC_PER_QUEUE).
	--
	-- Notice that, this argument must be lower or equal to
	-- CONFIG_RTE_MEMPOOL_CACHE_MAX_SIZE and n / 1.5.
	-- It is advised to choose cache_size to have "n modulo cache_size == 0":
	-- if this is not the case, some elements will always stay in the pool
	-- and will never be used. Here, n is gatekeeper_mbuf_size.
	--
	-- The maximum cache size can be adjusted in DPDK's .config file:
	-- CONFIG_RTE_MEMPOOL_CACHE_MAX_SIZE.
	gatekeeper_conf.gatekeeper_cache_size = 512
end

function gatekeeper_init()

	gatekeeper_config_init()

	-- When gatekeeper_server is true,
	-- Gatekeeper will run as a Gatekeeper server.
	-- Otherwise, it will run as a grantor server.
	local gatekeeper_server = true

	local netf = require("net")
	local net_conf = netf(gatekeeper_server)

	local numa_table = gatekeeper.get_numa_table(net_conf)

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
			gatekeeper.alloc_lcores_from_same_numa(numa_table,
				n_lcores + 2)
		local sol_lcore = table.remove(gk_lcores)
		local ggu_lcore = table.remove(gk_lcores)

		local solf = require("sol")
		local sol_conf = solf(net_conf, sol_lcore)

		local gkf = require("gk")
		gk_conf = gkf(net_conf, sol_conf, gk_lcores)

		local gguf = require("ggu")
		local ggu_conf = gguf(net_conf, gk_conf, ggu_lcore)
	else
		local gtf = require("gt")
		gt_conf = gtf(net_conf, numa_table)
	end

	-- Allocate CPS after to increase the change that the LLS block is
	-- allocated in the same NUMA node as the GK/GT/GK-GT-unit blocks.
	local cpsf = require("cps")
	local cps_conf = cpsf(net_conf, gk_conf, gt_conf, lls_conf, numa_table)

	local dyf = require("dyn_cfg")
	local dy_conf = dyf(gk_conf, numa_table)

	return 0
end
