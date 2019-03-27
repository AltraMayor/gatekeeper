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

function alloc_lcores_from_same_numa (numa_table, n)
	for numa, lcores in all_ipairs(numa_table) do
		if #lcores >= n then
			local a1, a2 = split_array(lcores, n)
			numa_table[numa] = a2
			numa_table["__net_conf"].numa_used[numa] = true
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
	/* This struct has hidden fields. */
};

struct net_config {
	int          back_iface_enabled;
	int          guarantee_random_entropy;
	unsigned int num_attempts_link_get;
	bool         *numa_used;
	uint32_t     log_level;
	int          log_type;
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
	unsigned int max_num_ipv4_fib_entries;
	unsigned int max_num_ipv6_fib_entries;
	unsigned int flow_table_full_scan_ms;
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
	unsigned int mailbox_max_pkt_burst;
	unsigned int mailbox_max_entries_exp;
	unsigned int mailbox_mem_cache_size;
	unsigned int mailbox_burst_size;
	unsigned int lls_cache_records;
	unsigned int lls_cache_scan_interval_sec;
	uint32_t     log_level;
	int          log_type;
	uint32_t     log_ratelimit_interval_ms;
	uint32_t     log_ratelimit_burst;
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
	uint16_t     gt_max_pkt_burst;
	unsigned int batch_interval;
	unsigned int max_ggu_notify_pkts;
	unsigned int mailbox_max_entries_exp;
	unsigned int mailbox_mem_cache_size;
	unsigned int mailbox_burst_size;
	uint32_t     log_level;
	int          log_type;
	uint32_t     log_ratelimit_interval_ms;
	uint32_t     log_ratelimit_burst;
	/* This struct has hidden fields. */
};

struct cps_config {
	unsigned int lcore_id;
	uint16_t     tcp_port_bgp;
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
	/* This struct has hidden fields. */
};

struct sol_config {
	unsigned int lcore_id;
	unsigned int pri_req_max_len;
	double       req_bw_rate;
	unsigned int enq_burst_size;
	unsigned int deq_burst_size;
	double       tb_rate_approx_err;
	double       req_channel_bw_mbps;
	unsigned int mailbox_mem_cache_size;
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
	const char **pci_addrs, uint8_t num_pci_addrs,
	const char **ip_cidrs, uint8_t num_ip_cidrs, uint16_t vlan_tag);

bool ipv4_configured(struct net_config *net_conf);
bool ipv6_configured(struct net_config *net_conf);
struct net_config *get_net_conf(void);
struct gatekeeper_if *get_if_front(struct net_config *net_conf);
struct gatekeeper_if *get_if_back(struct net_config *net_conf);
int gatekeeper_init_network(struct net_config *net_conf);

struct gk_config *alloc_gk_conf(void);
void set_gk_request_timeout(unsigned int request_timeout_sec,
	struct gk_config *gk_conf);
int run_gk(struct net_config *net_conf, struct gk_config *gk_conf,
	struct sol_config *sol_conf);

struct ggu_config *alloc_ggu_conf(void);
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
int run_dynamic_config(struct gk_config *gk_conf, struct gt_config *gt_conf,
	const char *server_path, const char *lua_dy_base_dir,
	const char *dynamic_config_file, struct dynamic_config *dy_conf);

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

function init_iface(iface, name, ports, cidrs, vlan_tag)
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
		ip_cidrs, #cidrs, vlan_tag)
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
