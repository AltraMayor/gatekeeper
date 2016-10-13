local ffi = require("ffi")

-- Structs
-- TODO Define the C data structures for other functional blocks.
ffi.cdef[[

struct gatekeeper_if {
	char	**pci_addrs;
	uint8_t	num_ports;
	char	*name;
	/* This struct has hidden fields. */
};

struct net_config {
	uint16_t num_rx_queues;
	uint16_t num_tx_queues;
	/* This struct has hidden fields. */
};

struct gk_config {
	unsigned int lcore_start_id;
	unsigned int lcore_end_id;
	/* This struct has hidden fields. */
};

]]

-- Functions and wrappers
-- TODO Define the C functions for other functional blocks.
ffi.cdef[[

int lua_init_iface(struct gatekeeper_if *iface, const char *iface_name,
	const char **pci_addrs, uint8_t num_pci_addrs);
void lua_free_iface(struct gatekeeper_if *iface);

struct net_config *get_net_conf(void);
struct gatekeeper_if *get_if_front(struct net_config *net_conf);
struct gatekeeper_if *get_if_back(struct net_config *net_conf);
int gatekeeper_init_network(struct net_config *net_conf);

struct gk_config *alloc_gk_conf(void);
int run_gk(struct gk_config *gk_conf);

]]

return ffi.C
