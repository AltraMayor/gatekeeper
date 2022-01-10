module("staticlib", package.seeall)

--
-- Functions to allocate lcores
--

function get_numa_table (net_conf)
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
	numa_table["__net_conf"] = net_conf
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

local function alloc_lcores_at_numa (numa_table, numa, n)
	local a1, a2 = split_array(numa_table[numa], n)
	numa_table[numa] = a2
	numa_table["__net_conf"].numa_used[numa] = true
	return a1
end

function alloc_lcores_from_same_numa (numa_table, n)
	for numa, lcores in all_ipairs(numa_table) do
		if #lcores >= n then
			return alloc_lcores_at_numa(numa_table, numa, n)
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

function count_numa_nodes (numa_table)
	local count = 0
	for numa, lcores in all_ipairs(numa_table) do
		count = count + 1
	end
	return count
end

function alloc_lcores_evenly_from_all_numa_nodes (numa_table, n,
		fixed_lcores_per_numa)
	local num_numa_nodes = count_numa_nodes(numa_table)
	local q = n / num_numa_nodes
	local r = n % num_numa_nodes
	local i = 0
	local res = {["__net_conf"] = numa_table["__net_conf"], }
	for numa, lcores in all_ipairs(numa_table) do
		local lcores_needed = q + ((i < r) and 1 or 0)
		if lcores_needed > 0 then
			lcores_needed = lcores_needed + fixed_lcores_per_numa
		else
			break
		end
		if #lcores >= lcores_needed then
			res[numa] = alloc_lcores_at_numa(numa_table, numa, lcores_needed)
		else
			error("There is not enough lcores");
		end
		i = i + 1
	end
	return res
end

local function append_array (a, b)
	for i, v in ipairs(b) do
		table.insert(a, v)
	end
end

function convert_numa_table_to_array (numa_table)
	local res = {}
	for numa, lcores in all_ipairs(numa_table) do
		append_array(res, lcores)
	end
	return res
end

function gk_sol_map (gk_lcores, sol_lcores)
	local m = {}
	local sol_allocated = {}

	if #gk_lcores % #sol_lcores ~= 0 then
		print("Warning: uneven GK-to-SOL blocks assignment");
	end

	for i, v in ipairs(sol_lcores) do
		sol_allocated[i] = 0
	end

	for i1, v1 in ipairs(gk_lcores) do
		local idx
		local socket_id = rte_lcore_to_socket_id(v1)

		for i2, v2 in ipairs(sol_lcores) do
			if rte_lcore_to_socket_id(v2) == socket_id and
					(idx == nil or sol_allocated[i2] <
						sol_allocated[idx]) then
				idx = i2
			end
		end

		if idx == nil then
			error("No SOL block allocated at NUMA node " .. socket_id)
		end

		m[i1] = idx
		sol_allocated[idx] = sol_allocated[idx] + 1
	end

	for i, v in ipairs(sol_allocated) do
		if v == 0 then
			print("Warning: SOL block at lcore " .. sol_lcores[i] ..
				" has zero GK block allocated to it");
		end
	end

	return m
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

enum log_levels {
	/* Corresponding to the values in rte_log.h. */
	RTE_LOG_EMERG = 1U,   /* System is unusable. */
	RTE_LOG_ALERT = 2U,   /* Action must be taken immediately. */
	RTE_LOG_CRIT = 3U,    /* Critical conditions. */
	RTE_LOG_ERR = 4U,     /* Error conditions. */
	RTE_LOG_WARNING = 5U, /* Warning conditions. */
	RTE_LOG_NOTICE = 6U,  /* Normal but significant condition. */
	RTE_LOG_INFO = 7U,    /* Informational. */
	RTE_LOG_DEBUG = 8U,   /* Debug-level messages. */
};

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

enum file_modes {
	/* RWX mask for owner. */
	S_IRWXU = 0000700,
	/* R for owner. */
	S_IRUSR = 0000400,
	/* W for owner. */
	S_IWUSR = 0000200,
	/* X for owner. */
	S_IXUSR = 0000100,
	/* RWX mask for group. */
	S_IRWXG = 0000070,
	/* R for group. */
	S_IRGRP = 0000040,
	/* W for group. */
	S_IWGRP = 0000020,
	/* X for group. */
	S_IXGRP = 0000010,
	/* RWX mask for other. */
	S_IRWXO = 0000007,
	/* R for other. */
	S_IROTH = 0000004,
	/* W for other. */
	S_IWOTH = 0000002,
	/* X for other. */
	S_IXOTH = 0000001,
	/* Set user id on execution. */
	S_ISUID = 0004000,
	/* Set group id on execution. */
	S_ISGID = 0002000,
	/* Save swapped text even after use. */
	S_ISVTX = 0001000,
};

struct gatekeeper_if {
	char     **pci_addrs;
	uint8_t  num_ports;
	char     *name;
	uint16_t num_rx_queues;
	uint16_t num_tx_queues;
	uint16_t total_pkt_burst;
	uint32_t arp_cache_timeout_sec;
	uint32_t nd_cache_timeout_sec;
	uint32_t bonding_mode;
	int      vlan_insert;
	uint16_t mtu;
	uint8_t  ipv6_default_hop_limits;
	uint16_t num_rx_desc;
	uint16_t num_tx_desc;
	bool     ipv4_hw_udp_cksum;
	bool     ipv6_hw_udp_cksum;
	bool     ipv4_hw_cksum;
	/* This struct has hidden fields. */
};

struct net_config {
	int          back_iface_enabled;
	int          guarantee_random_entropy;
	unsigned int num_attempts_link_get;
	bool         *numa_used;
	uint32_t     log_level;
	uint32_t     rotate_log_interval_sec;
	/* This struct has hidden fields. */
};

struct gk_config {
	unsigned int flow_ht_size;
	unsigned int max_num_ipv4_rules;
	unsigned int num_ipv4_tbl8s;
	unsigned int max_num_ipv6_rules;
	unsigned int num_ipv6_tbl8s;
	unsigned int max_num_ipv6_neighbors;
	unsigned int flow_table_scan_iter;
	unsigned int scan_del_thresh;
	uint16_t     front_max_pkt_burst;
	uint16_t     back_max_pkt_burst;
	uint32_t     front_icmp_msgs_per_sec;
	uint32_t     front_icmp_msgs_burst;
	uint32_t     back_icmp_msgs_per_sec;
	uint32_t     back_icmp_msgs_burst;
	unsigned int mailbox_max_entries_exp;
	unsigned int mailbox_mem_cache_size;
	unsigned int mailbox_burst_size;
	uint32_t     log_level;
	int          log_type;
	uint32_t     log_ratelimit_interval_ms;
	uint32_t     log_ratelimit_burst;
	unsigned int basic_measurement_logging_ms;
	uint8_t      fib_dump_batch_size;
	/* This struct has hidden fields. */
};

struct ggu_config {
	unsigned int lcore_id;
	uint16_t     ggu_src_port;
	uint16_t     ggu_dst_port;
	uint16_t     max_pkt_burst;
	unsigned int mailbox_max_entries_exp;
	unsigned int mailbox_mem_cache_size;
	unsigned int mailbox_burst_size;
	uint32_t     log_level;
	int          log_type;
	uint32_t     log_ratelimit_interval_ms;
	uint32_t     log_ratelimit_burst;
	/* This struct has hidden fields. */
};

struct lls_config {
	unsigned int lcore_id;
	uint16_t     front_max_pkt_burst;
	uint16_t     back_max_pkt_burst;
	unsigned int mailbox_max_pkt_sub;
	unsigned int mailbox_max_entries_exp;
	unsigned int mailbox_mem_cache_size;
	unsigned int mailbox_burst_size;
	unsigned int max_num_cache_records;
	unsigned int cache_scan_interval_sec;
	uint32_t     log_level;
	int          log_type;
	uint32_t     log_ratelimit_interval_ms;
	uint32_t     log_ratelimit_burst;
	uint32_t     front_icmp_msgs_per_sec;
	uint32_t     front_icmp_msgs_burst;
	uint32_t     back_icmp_msgs_per_sec;
	uint32_t     back_icmp_msgs_burst;
	/* This struct has hidden fields. */
};

struct gt_config {
	uint16_t     ggu_src_port;
	uint16_t     ggu_dst_port;
	int          max_num_ipv6_neighbors;
	uint32_t     frag_scan_timeout_ms;
	uint32_t     frag_bucket_num;
	uint32_t     frag_bucket_entries;
	uint32_t     frag_max_entries;
	uint32_t     frag_max_flow_ttl_ms;
	uint16_t     max_pkt_burst;
	unsigned int batch_interval;
	unsigned int max_ggu_notify_pkts;
	unsigned int mailbox_max_entries_exp;
	unsigned int mailbox_mem_cache_size;
	unsigned int mailbox_burst_size;
	uint32_t     log_level;
	int          log_type;
	uint32_t     log_ratelimit_interval_ms;
	uint32_t     log_ratelimit_burst;
	bool         reassembling_enabled;
	/* This struct has hidden fields. */
};

struct cps_config {
	unsigned int lcore_id;
	uint32_t     log_level;
	int          log_type;
	uint32_t     log_ratelimit_interval_ms;
	uint32_t     log_ratelimit_burst;
	uint16_t     front_max_pkt_burst;
	uint16_t     back_max_pkt_burst;
	unsigned int num_attempts_kni_link_set;
	unsigned int max_rt_update_pkts;
	unsigned int scan_interval_sec;
	unsigned int mailbox_max_entries_exp;
	unsigned int mailbox_mem_cache_size;
	unsigned int mailbox_burst_size;
	uint32_t     nl_pid;
	unsigned int arp_max_entries_exp;
	unsigned int nd_max_entries_exp;
	/* This struct has hidden fields. */
};

struct dynamic_config {
	unsigned int     lcore_id;
	struct gk_config *gk;
	struct gt_config *gt;
	uint32_t         log_level;
	int              log_type;
	uint32_t         log_ratelimit_interval_ms;
	uint32_t         log_ratelimit_burst;
	unsigned int     mailbox_max_entries_exp;
	unsigned int     mailbox_mem_cache_size;
	unsigned int     mailbox_burst_size;
	/* This struct has hidden fields. */
};

struct sol_config {
	unsigned int pri_req_max_len;
	double       req_bw_rate;
	unsigned int enq_burst_size;
	unsigned int deq_burst_size;
	double       tb_rate_approx_err;
	double       req_channel_bw_mbps;
	uint32_t     log_level;
	int          log_type;
	uint32_t     log_ratelimit_interval_ms;
	uint32_t     log_ratelimit_burst;
	/* This struct has hidden fields. */
};

]]

-- Functions and wrappers
ffi.cdef[[

void rte_log_set_global_level(uint32_t log_level);
uint32_t rte_log_get_global_level(void);

int rte_log_set_level(uint32_t type, uint32_t level);
int rte_log_get_level(uint32_t type);

int lua_init_iface(struct gatekeeper_if *iface, const char *iface_name,
	const char **pci_addrs, uint8_t num_pci_addrs, const char **ip_cidrs,
	uint8_t num_ip_cidrs, uint16_t ipv4_vlan_tag, uint16_t ipv6_vlan_tag);

bool ipv4_configured(struct net_config *net_conf);
bool ipv6_configured(struct net_config *net_conf);
struct net_config *get_net_conf(void);
struct gatekeeper_if *get_if_front(struct net_config *net_conf);
struct gatekeeper_if *get_if_back(struct net_config *net_conf);
int gatekeeper_setup_user(struct net_config *net_conf,
	const char *user);
int gatekeeper_init_network(struct net_config *net_conf);

struct gk_config *alloc_gk_conf(void);
int gk_load_bpf_flow_handler(struct gk_config *gk_conf, unsigned int index,
	const char *filename, int jit);
int run_gk(struct net_config *net_conf, struct gk_config *gk_conf,
	struct sol_config *sol_conf);

struct ggu_config *alloc_ggu_conf(unsigned int lcore);
int run_ggu(struct net_config *net_conf,
	struct gk_config *gk_conf, struct ggu_config *ggu_conf);
int cleanup_ggu(struct ggu_config *ggu_conf);

struct lls_config *get_lls_conf(void);
int run_lls(struct net_config *net_conf, struct lls_config *lls_conf);

struct gt_config *alloc_gt_conf(void);
int run_gt(struct net_config *net_conf, struct gt_config *gt_conf,
	const char *lua_base_directory, const char *lua_policy_file);

struct cps_config *get_cps_conf(void);
int run_cps(struct net_config *net_conf, struct gk_config *gk_conf,
	struct gt_config *gt_conf, struct cps_config *cps_conf,
	struct lls_config *lls_conf, const char *kni_kmod_path);
struct dynamic_config *get_dy_conf(void);
void set_dyc_timeout(unsigned sec, unsigned usec,
	struct dynamic_config *dy_conf);
int run_dynamic_config(struct net_config *net_conf,
	struct gk_config *gk_conf, struct gt_config *gt_conf,
	const char *server_path, const char *lua_dy_base_dir,
	const char *dynamic_config_file, struct dynamic_config *dy_conf,
	int mode);

struct sol_config *alloc_sol_conf(void);
int run_sol(struct net_config *net_conf, struct sol_config *sol_conf);

]]

c = ffi.C

--
-- Network configuration functions
--

local ifaces = require("if_map")

function check_ifaces(front_ports, back_ports)
	for i1, v1 in ipairs(front_ports) do
		pci1 = ifaces[v1]
		if pci1 == nil then
			error("There is no map for " .. v1 .. " in the front interface configuration")
		end

		for i2, v2 in ipairs(back_ports) do
			pci2 = ifaces[v2]
			if pci2 == nil then
				error("There is no map for " .. v2 .. " in the back interface configuration")
			end

			if pci1 == pci2 then
				error("Configured interfaces on the front [" .. v1 .. " (" .. pci1 .. ")] and back [" .. v2 .. " (" .. pci2 .. ")] are the same")
			end
		end
	end
end

function init_iface(iface, name, ports, cidrs, ipv4_vlan_tag, ipv6_vlan_tag)
	local pci_strs = ffi.new("const char *[" .. #ports .. "]")
	for i, v in ipairs(ports) do
		local pci_addr = ifaces[v]
		if pci_addr == nil then
			error("There is no map for interface " .. v)
		end

		for i2, v2 in ipairs(ports) do
			if i2 > i and pci_addr == ifaces[v2] then
				error("Duplicate interfaces: " .. v .. " and " .. v2 .. " map to the same PCI address (" .. pci_addr .. ") in the " .. name .. " configuration")
			end
		end

		pci_strs[i - 1] = pci_addr
	end

	local ip_cidrs = ffi.new("const char *[" .. #cidrs .. "]")
	for i, v in ipairs(cidrs) do
		ip_cidrs[i - 1] = v
	end

	local ret = c.lua_init_iface(iface, name, pci_strs, #ports,
		ip_cidrs, #cidrs, ipv4_vlan_tag, ipv6_vlan_tag)
	if ret < 0 then
		error("Failed to initilialize " .. name .. " interface")
	end
	return ret
end

function get_front_burst_config(max_pkt_burst_front, net_conf)
	local front_iface = c.get_if_front(net_conf)
	return math.max(max_pkt_burst_front, front_iface.num_ports)
end

function get_back_burst_config(max_pkt_burst_back, net_conf)
	if not net_conf.back_iface_enabled then
		error("One can only have max_pkt_burst_back when the back network is enabled")
	end

	local back_iface = c.get_if_back(net_conf)
	return math.max(max_pkt_burst_back, back_iface.num_ports)
end
