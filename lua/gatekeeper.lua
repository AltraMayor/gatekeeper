module(..., package.seeall)

--
-- Functions to allocate lcores
--

function get_numa_table ()
	local numa_table = {}
	for _, lcore in ipairs(list_lcores()) do
		local socket_id = rte_lcore_to_socket_id(lcore)
		local t = numa_table[socket_id]
		if t == nil then
			numa_table[socket_id] = {lcore}
		else
			table.insert(t, lcore)
		end
	end
	return numa_table
end

function split_array (array, split_pos)
	local a1 = {}
	local a2 = {}
	for i, v in ipairs(array) do
		if i <= split_pos then
			table.insert(a1, v)
		else
			table.insert(a2, v)
		end
	end
	if next(a2) == nil then
		-- a2 is empty.
		a2 = nil
	end
	return a1, a2
end

-- This iterator works like ipairs(), but
--	(1) it skips nil entries instead of stopping, and
--	(2) it starts at index zero instead of one.
function all_ipairs (a)
	return function (last_index, cur_index)
		while true do
			cur_index = cur_index + 1
 			if cur_index > last_index then
				return nil
			end
			local ret = a[cur_index]
			if ret ~= nil then
				return cur_index, ret
			end
		end
	end, table.maxn(a), -1
end

function alloc_lcores_from_same_numa (numa_table, n)
	for numa, lcores in all_ipairs(numa_table) do
		if #lcores >= n then
			local a1, a2 = split_array(lcores, n)
			numa_table[numa] = a2
			return a1
		end
	end
	return nil
end

function alloc_an_lcore (numa_table)
	local lcore_t = alloc_lcores_from_same_numa(numa_table, 1)
	if lcore_t == nil then
		error("There is not enough lcores");
	end
	return lcore_t[1]
end

function print_lcore_array (array)
	io.write("Array: ")
	for i, v in ipairs(array) do
		io.write("[", i, "]=", v, "\t")
	end
	io.write("\n")
end

function print_numa_table (numa_table)
	for numa, lcores in all_ipairs(numa_table) do
		io.write("NUMA ", numa, ":\t")
		for _, lcore in ipairs(lcores) do
			io.write(lcore, "\t")
		end
		io.write("\n")
	end
end

--
-- C functions exported through FFI
--

local ffi = require("ffi")

-- Structs
ffi.cdef[[

enum bonding_modes {
	/* Corresponding to the values in rte_eth_bond.h. */
	BONDING_MODE_ROUND_ROBIN = 0,
	BONDING_MODE_ACTIVE_BACKUP = 1,
	BONDING_MODE_BALANCE = 2,
	BONDING_MODE_BROADCAST = 3,
	BONDING_MODE_8023AD = 4,
	BONDING_MODE_TLB = 5,
	BONDING_MODE_ALB = 6,
};

struct gatekeeper_if {
	char     **pci_addrs;
	uint8_t  num_ports;
	char     *name;
	uint16_t num_rx_queues;
	uint16_t num_tx_queues;
	uint32_t arp_cache_timeout_sec;
	uint32_t nd_cache_timeout_sec;
	uint32_t bonding_mode;
	/* This struct has hidden fields. */
};

struct net_config {
	int back_iface_enabled;
	/* This struct has hidden fields. */
};

struct gk_config {
	unsigned int flow_ht_size;
	unsigned int max_num_ipv4_rules;
	unsigned int num_ipv4_tbl8s;
	unsigned int max_num_ipv6_rules;
	unsigned int num_ipv6_tbl8s;
	unsigned int max_num_ipv6_neighbors;
	unsigned int gk_max_num_ipv4_fib_entries;
	unsigned int gk_max_num_ipv6_fib_entries;
	/* This struct has hidden fields. */
};

struct ggu_config {
	unsigned int      lcore_id;
	uint16_t          ggu_src_port;
	uint16_t          ggu_dst_port;
	/* This struct has hidden fields. */
};

struct lls_config {
	unsigned int lcore_id;
	int          debug;
	/* This struct has hidden fields. */
};

struct gt_config {
	uint16_t     ggu_src_port;
	uint16_t     ggu_dst_port;
	/* This struct has hidden fields. */
};

struct cps_config {
	unsigned int lcore_id;
	uint16_t     tcp_port_bgp;
	int          debug;
	/* This struct has hidden fields. */
};

struct dynamic_config {
	unsigned int     lcore_id;
	struct gk_config *gk;
	/* This struct has hidden fields. */
};

struct sol_config {
	unsigned int lcore_id;
	unsigned int pri_req_max_len;
	double       req_bw_rate;
	unsigned int enq_burst_size;
	unsigned int deq_burst_size;
	/* This struct has hidden fields. */
};

]]

-- Functions and wrappers
ffi.cdef[[

int lua_init_iface(struct gatekeeper_if *iface, const char *iface_name,
	const char **pci_addrs, uint8_t num_pci_addrs,
	const char **ip_cidrs, uint8_t num_ip_cidrs);
void lua_free_iface(struct gatekeeper_if *iface);

bool ipv4_configured(struct net_config *net_conf);
bool ipv6_configured(struct net_config *net_conf);
struct net_config *get_net_conf(void);
struct gatekeeper_if *get_if_front(struct net_config *net_conf);
struct gatekeeper_if *get_if_back(struct net_config *net_conf);
int gatekeeper_init_network(struct net_config *net_conf);

struct gk_config *alloc_gk_conf(void);
int run_gk(struct net_config *net_conf, struct gk_config *gk_conf,
	struct sol_config *sol_conf);

struct ggu_config *alloc_ggu_conf(void);
int run_ggu(struct net_config *net_conf,
	struct gk_config *gk_conf, struct ggu_config *ggu_conf);
int cleanup_ggu(struct ggu_config *ggu_conf);

struct lls_config *get_lls_conf(void);
int run_lls(struct net_config *net_conf, struct lls_config *lls_conf);

struct gt_config *alloc_gt_conf(void);
int run_gt(struct net_config *net_conf, struct gt_config *gt_conf);

struct cps_config *get_cps_conf(void);
int run_cps(struct net_config *net_conf, struct cps_config *cps_conf,
	struct lls_config *lls_conf, const char *kni_kmod_path);
struct dynamic_config *get_dy_conf(void);
void set_dyc_timeout(unsigned sec, unsigned usec,
	struct dynamic_config *dy_conf);
int run_dynamic_config(struct gk_config *gk_conf,
	const char *server_path, struct dynamic_config *dy_conf);

struct sol_config *alloc_sol_conf(void);
int run_sol(struct net_config *net_conf, struct sol_config *sol_conf);

]]

c = ffi.C

--
-- Network configuration functions
--

local ifaces = require("if_map")

function init_iface(iface, name, ports, cidrs)
	local pci_strs = ffi.new("const char *[" .. #ports .. "]")
	for i, v in ipairs(ports) do
		local pci_addr = ifaces[v]
		if pci_addr == nil then
			error("There is no map for interface " .. v)
		end
		pci_strs[i - 1] = pci_addr
	end

	local ip_cidrs = ffi.new("const char *[" .. #cidrs .. "]")
	for i, v in ipairs(cidrs) do
		ip_cidrs[i - 1] = v
	end

	local ret = c.lua_init_iface(iface, name, pci_strs, #ports,
		ip_cidrs, #cidrs)
	if ret < 0 then
		error("Failed to initilialize " .. name .. " interface")
	end
	return ret
end
