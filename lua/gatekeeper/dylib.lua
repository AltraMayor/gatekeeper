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

-- Bound the output of the FIB table to the maximum size of
-- a message of the dynamic configuration block.
function bound_fib_dump_output(acc)
	local next_stop = acc.next_stop
	local total_rows = #acc

	if next_stop == nil then
		next_stop = 1000
		acc.next_stop = next_stop
		acc.total_rows = 0
	end

	if total_rows < next_stop then
		return false, acc
	end

	if acc.total_rows ~= 0 then
		-- Subtract one because acc[1] is
		-- the concatenated output of acc.total_rows rows.
		total_rows = acc.total_rows + total_rows - 1
	end

	local output = table.concat(acc)
	local output_len = string.len(output)
	acc = { [1] = output } -- Free previous acc.
	if output_len >= c.MSG_MAX_LEN then
		return true, acc
	end

	-- Find the new acc.next_stop
	local avg_len_per_row = output_len / total_rows
	next_stop = math.ceil(
		((c.MSG_MAX_LEN - output_len) / avg_len_per_row)
		-- Add 1% to next_stop to increase the chance that
		-- the next stop is the last stop.
		* 1.01)
	if next_stop <= 0 then
		next_stop = 1
	end
	-- Add one because acc already includes acc[1].
	acc.next_stop = next_stop + 1

	acc.total_rows = total_rows
	return false, acc
end

-- The following is an example function that can be used as
-- the callback function of list_gk_fib4() and list_gk_fib6().

-- Parameter fib_dump_entry is going to be released after
-- print_fib_dump_entry() returns, so don't keep references to fib_dump_entry
-- or any of the data reachable through its fields.

function print_fib_dump_entry(fib_dump_entry, acc)
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

	return bound_fib_dump_output(acc)
end

-- The following is an example function that can be used as
-- the callback function of list_gk_neighbors4() and list_gk_neighbors6().

-- Parameter neighbor_dump_entry is going to be released after
-- print_neighbor_dump_entry() returns, so don't keep references to
-- neighbor_dump_entry or any of the data reachable through its fields.

function print_neighbor_dump_entry(neighbor_dump_entry, acc)
	acc[#acc + 1] = "Neighbor Ethernet cache entry: [state: "
	acc[#acc + 1] = neighbor_dump_entry.stale and "stale" or "fresh"
	acc[#acc + 1] = ", neighbor ip: "
	acc[#acc + 1] = dylib.ip_format_addr(neighbor_dump_entry.neigh_ip)
	acc[#acc + 1] = ", d_addr: "
	acc[#acc + 1] = dylib.ether_format_addr(neighbor_dump_entry.d_addr)
	acc[#acc + 1] = ", action: "
	acc[#acc + 1] = fib_action_to_str(neighbor_dump_entry.action)
	acc[#acc + 1] = "]\n"
	return acc
end

-- The following is an example function that can be used as
-- the callback function of list_lls_arp() and list_lls_nd().

-- Parameter lls_dump_entry is going to be released after
-- print_lls_dump_entry() returns, so don't keep references to
-- lls_dump_entry or any of the data reachable through its fields.

function print_lls_dump_entry(lls_dump_entry, acc)
	acc[#acc + 1] = "LLS cache entry: [state: "
	acc[#acc + 1] = lls_dump_entry.stale and "stale" or "fresh"
	acc[#acc + 1] = ", ip: "
	acc[#acc + 1] = dylib.ip_format_addr(lls_dump_entry.addr)
	acc[#acc + 1] = ", mac: "
	acc[#acc + 1] = dylib.ether_format_addr(lls_dump_entry.ha)
	acc[#acc + 1] = ", port: "
	acc[#acc + 1] = tostring(lls_dump_entry.port_id)
	acc[#acc + 1] = "]\n"
	return acc
end

function update_gt_lua_states_incrementally(gt_conf, lua_code, is_returned)
	dylib.internal_update_gt_lua_states_incrementally(gt_conf,
		string.dump(lua_code), is_returned)
end
