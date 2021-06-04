module("dylib", package.seeall)

--
-- C functions exported through FFI
--

local ffi = require("ffi")

-- Structs
ffi.cdef[[
static const uint16_t MSG_MAX_LEN = (uint16_t)~0U;

static const int ETHER_ADDR_LEN = 6;

enum gk_fib_action {
	GK_FWD_GRANTOR,
	GK_FWD_GATEWAY_FRONT_NET,
	GK_FWD_GATEWAY_BACK_NET,
	GK_FWD_NEIGHBOR_FRONT_NET,
	GK_FWD_NEIGHBOR_BACK_NET,
	GK_DROP,
	GK_FIB_MAX,
};

struct rte_ether_addr {
	uint8_t addr_bytes[ETHER_ADDR_LEN];
} __attribute__((__packed__));

struct in_addr {
	uint32_t s_addr;
};

struct in6_addr {
	unsigned char s6_addr[16];
};

struct ipaddr {
	uint16_t proto;
	union {
		struct in_addr  v4;
		struct in6_addr v6;
	} ip;
};

struct fib_dump_addr_set {
	struct ipaddr grantor_ip;
	struct ipaddr nexthop_ip;
	struct rte_ether_addr d_addr;
	bool          stale;
};

struct gk_fib_dump_entry {
	struct ipaddr addr;
	int           prefix_len;
	enum gk_fib_action action;
	unsigned int  num_addr_sets;
	struct fib_dump_addr_set addr_sets[0];
};

struct gk_neighbor_dump_entry {
	bool          stale;
	enum gk_fib_action action;
	struct ipaddr neigh_ip;
	struct rte_ether_addr d_addr;
};

struct lls_dump_entry {
	bool                  stale;
	uint16_t              port_id;
	struct ipaddr         addr;
	struct rte_ether_addr ha;
};

]]

-- Functions and wrappers
ffi.cdef[[

int add_fib_entry(const char *prefix, const char *gt_ip, const char *gw_ip,
	enum gk_fib_action action, struct gk_config *gk_conf);
int del_fib_entry(const char *ip_prefix, struct gk_config *gk_conf);

int gk_flush_flow_table(const char *src_prefix,
	const char *dst_prefix, struct gk_config *gk_conf);
int gk_log_flow_state(const char *src_addr,
	const char *dst_addr, struct gk_config *gk_conf);

int gk_load_bpf_flow_handler(struct gk_config *gk_conf, unsigned int index,
	const char *filename, int jit);
int gk_unload_bpf_flow_handler(struct gk_config *gk_conf, unsigned int index);
]]

c = ffi.C

function fib_action_to_str(fib_action)
	local res

	if fib_action == c.GK_FWD_GRANTOR then
		res = "FWD_GRANTOR (0)"
	elseif fib_action == c.GK_FWD_GATEWAY_FRONT_NET then
		res = "FWD_GATEWAY_FRONT_NET (1)"
	elseif fib_action == c.GK_FWD_GATEWAY_BACK_NET then
		res = "FWD_GATEWAY_BACK_NET (2)"
	elseif fib_action == c.GK_FWD_NEIGHBOR_FRONT_NET then
		res = "FWD_NEIGHBOR_FRONT_NET (3)"
	elseif fib_action == c.GK_FWD_NEIGHBOR_BACK_NET then
		res = "FWD_NEIGHBOR_BACK_NET (4)"
	elseif fib_action == c.GK_DROP then
		res = "DROP (5)"
	else
		res = "INVALID (" .. tostring(fib_action) .. ")"
	end

	return res
end

-- The following is an example function that can be used as
-- the callback function of list_gk_fib4() and list_gk_fib6().

-- Parameter fib_dump_entry is going to be released after
-- print_fib_dump_entry() returns, so don't keep references to fib_dump_entry
-- or any of the data reachable through its fields.

function print_fib_dump_entry(fib_dump_entry, acc)
	if acc.done then
		return acc
	end

	acc[#acc + 1] = "FIB entry for IP prefix: "
	acc[#acc + 1] = dylib.ip_format_addr(fib_dump_entry.addr)
	acc[#acc + 1] = "/"
	acc[#acc + 1] = tostring(fib_dump_entry.prefix_len)
	acc[#acc + 1] = " with action "
	acc[#acc + 1] = fib_action_to_str(fib_dump_entry.action)

	for i = 0,fib_dump_entry.num_addr_sets - 1,1 do
		if fib_dump_entry.action == c.GK_FWD_GRANTOR then
			acc[#acc + 1] = "\n\tGrantor IP address: "
			acc[#acc + 1] = dylib.ip_format_addr(
				fib_dump_entry.addr_sets[i].grantor_ip)
		end
		acc[#acc + 1] = "\n\tEthernet cache entry: [state: "
		acc[#acc + 1] = fib_dump_entry.addr_sets[i].stale
			and "stale" or "fresh"
		acc[#acc + 1] = ", nexthop ip: "
		acc[#acc + 1] = dylib.ip_format_addr(
			fib_dump_entry.addr_sets[i].nexthop_ip)
		acc[#acc + 1] = ", d_addr: "
		acc[#acc + 1] = dylib.ether_format_addr(
			fib_dump_entry.addr_sets[i].d_addr)
		acc[#acc + 1] = "]"
	end
	acc[#acc + 1] = "\n"

	if #acc < 1000 then
		return acc
	end

	-- If the FIB table is too big to dump into a single message
	-- of the dynamic configuration block, ignore the following entries.
	acc = { [1] = table.concat(acc) }
	if string.len(acc[1]) >= c.MSG_MAX_LEN then
		acc.done = true
	end
	return acc
end

-- The following is an example function that can be used as
-- the callback function of list_gk_neighbors4() and list_gk_neighbors6().

-- Parameter neighbor_dump_entry is going to be released after
-- print_neighbor_dump_entry() returns, so don't keep references to
-- neighbor_dump_entry or any of the data reachable through its fields.

function print_neighbor_dump_entry(neighbor_dump_entry, acc)
	local stale = neighbor_dump_entry.stale and "stale" or "fresh"
	local neigh_ip = dylib.ip_format_addr(neighbor_dump_entry.neigh_ip)
	local d_buf = dylib.ether_format_addr(neighbor_dump_entry.d_addr)

	return acc .. "Neighbor Ethernet cache entry: [state: " .. stale ..
		", neighbor ip: " .. neigh_ip .. ", d_addr: " .. d_buf ..
		", action: " ..
		fib_action_to_str(neighbor_dump_entry.action) .. "]\n"
end

-- The following is an example function that can be used as
-- the callback function of list_lls_arp() and list_lls_nd().

-- Parameter lls_dump_entry is going to be released after
-- print_lls_dump_entry() returns, so don't keep references to
-- lls_dump_entry or any of the data reachable through its fields.

function print_lls_dump_entry(lls_dump_entry, acc)
	local stale = lls_dump_entry.stale and "stale" or "fresh"
	local ip = dylib.ip_format_addr(lls_dump_entry.addr)
	local ha = dylib.ether_format_addr(lls_dump_entry.ha)
	local port_id = lls_dump_entry.port_id

	return acc .. "LLS cache entry:" .. ": [state: " .. stale ..
		", ip: " .. ip .. ", mac: " .. ha ..
		", port: " .. port_id .. "]\n"
end

function update_gt_lua_states_incrementally(gt_conf, lua_code, is_returned)
	dylib.internal_update_gt_lua_states_incrementally(gt_conf,
		string.dump(lua_code), is_returned)
end
