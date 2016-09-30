local gatekeeperc = require("gatekeeperc")

local M = {}

-- Function that sets up the network.
function M.setup_block()

	-- Init the network configuration structure.
	local conf = gatekeeperc.get_net_conf()
	conf.num_rx_queues = 1
	conf.num_tx_queues = 1

	-- Set up the network.
	return gatekeeperc.gatekeeper_init_network(conf)
end

return M
