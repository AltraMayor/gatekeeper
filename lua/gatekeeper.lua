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

struct gatekeeper_if {
	char     **pci_addrs;
	uint8_t  num_ports;
	char     *name;
	uint16_t num_rx_queues;
	uint16_t num_tx_queues;
	uint32_t arp_cache_timeout_sec;
	/* This struct has hidden fields. */
};

struct net_config {
	int back_iface_enabled;
	/* This struct has hidden fields. */
};

struct gk_config {
	unsigned int flow_ht_size;
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

]]

-- Functions and wrappers
ffi.cdef[[

int lua_init_iface(struct gatekeeper_if *iface, const char *iface_name,
	const char **pci_addrs, uint8_t num_pci_addrs,
	const char **ip_addrs, uint8_t num_ip_addrs);
void lua_free_iface(struct gatekeeper_if *iface);

struct net_config *get_net_conf(void);
struct gatekeeper_if *get_if_front(struct net_config *net_conf);
struct gatekeeper_if *get_if_back(struct net_config *net_conf);
int gatekeeper_init_network(struct net_config *net_conf);

struct gk_config *alloc_gk_conf(void);
int run_gk(struct net_config *net_conf, struct gk_config *gk_conf);

struct ggu_config *alloc_ggu_conf(void);
int run_ggu(struct net_config *net_conf,
	struct gk_config *gk_conf, struct ggu_config *ggu_conf);
int cleanup_ggu(struct ggu_config *ggu_conf);

struct lls_config *get_lls_conf(void);
int run_lls(struct net_config *net_conf, struct lls_config *lls_conf);

]]

c = ffi.C

--
-- Network configuration functions
--

local ifaces = require("if_map")

function init_iface(iface, name, ports, ips)
	local pci_strs = ffi.new("const char *[" .. #ports .. "]")
	for i, v in ipairs(ports) do
		local pci_addr = ifaces[v]
		if pci_addr == nil then
			error("There is no map for interface " .. v)
		end
		pci_strs[i - 1] = pci_addr
	end

	local ip_strs = ffi.new("const char *[" .. #ips .. "]")
	for i, v in ipairs(ips) do
		ip_strs[i - 1] = v
	end

	return c.lua_init_iface(iface, name, pci_strs, #ports, ip_strs, #ips)
end
