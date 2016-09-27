local ffi = require("ffi")

-- Structs
-- TODO Define the C data structures for other functional blocks.
ffi.cdef[[

struct net_config {
	uint16_t		num_rx_queues;
	uint16_t		num_tx_queues;
	/*
	 * The fields below are for internal use.
	 * Configuration files should not refer to them.
	 */
	uint32_t		num_ports;
	struct rte_mempool 	**gatekeeper_pktmbuf_pool;
};

typedef struct {
	volatile int32_t cnt;
} rte_atomic32_t;

struct gk_config {
	unsigned int	lcore_start_id;
	unsigned int	lcore_end_id;
	/*
	 * The fields below are for internal use.
	 * Configuration files should not refer to them.
	 */
	rte_atomic32_t	ref_cnt;
};

]]

-- Functions and wrappers
-- TODO Define the C functions for other functional blocks.
ffi.cdef[[

struct net_config *get_net_conf(void);
int gatekeeper_init_network(struct net_config *net_conf);

struct gk_config *alloc_gk_conf(void);
int run_gk(struct gk_config *gk_conf);

]]

return ffi.C
