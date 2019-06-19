module("dylib", package.seeall)

--
-- C functions exported through FFI
--

local ffi = require("ffi")

-- Structs
ffi.cdef[[

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

struct gk_fib_dump_entry {
	struct ipaddr addr;
	int           prefix_len;
	struct ipaddr grantor_ip;
	bool          stale;
	struct ipaddr nexthop_ip;
	struct rte_ether_addr d_addr;
	enum gk_fib_action action;
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
	local ip_addr_str
	local d_buf
	local stale

	ip_addr_str = dylib.ip_format_addr(fib_dump_entry.addr)
	acc = acc .. "FIB entry for IP prefix: " .. ip_addr_str ..
		"/" .. fib_dump_entry.prefix_len .. " with action " ..
		fib_action_to_str(fib_dump_entry.action)

	if fib_dump_entry.action == c.GK_FWD_GRANTOR then
		ip_addr_str = dylib.ip_format_addr(fib_dump_entry.grantor_ip)
		acc = acc .. "\n\tGrantor IP address: " .. ip_addr_str
	end

	acc = acc .. "\n\tEthernet cache entry:"

	d_buf = dylib.ether_format_addr(fib_dump_entry.d_addr)
	stale = fib_dump_entry.stale and "stale" or "fresh"
	ip_addr_str = dylib.ip_format_addr(fib_dump_entry.nexthop_ip)
	acc = acc .. " [state: " .. stale .. ", nexthop ip: " ..
		ip_addr_str .. ", d_addr: " .. d_buf .. "]"

	return acc .. "\n"
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

function update_gt_lua_states_incrementally(gt_conf, lua_code)
	dylib.internal_update_gt_lua_states_incrementally(gt_conf,
		string.dump(lua_code))
end
