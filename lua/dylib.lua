module("dylib", package.seeall)

require "gatekeeper"

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

struct ether_addr {
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

struct gk_fib_ether_dump_entry {
	bool          stale;
	struct ipaddr nexthop_ip;
	struct ether_addr d_addr;
};

struct gk_fib_dump_entry {
	struct ipaddr addr;
	int           prefix_len;
	struct ipaddr grantor_ip;
	uint16_t      num_ether_entries;
	enum gk_fib_action action;
	struct gk_fib_ether_dump_entry *ether_tbl;
};

]]

-- Functions and wrappers
ffi.cdef[[

int add_fib_entry(const char *prefix, const char *gt_ip, const char *gw_ip,
	enum gk_fib_action action, struct gk_config *gk_conf);
int del_fib_entry(const char *ip_prefix, struct gk_config *gk_conf);

]]

c = ffi.C

-- Do not call this fuction directly!
-- Use iterator ethernet_entries() instead.
function ethernet_next (fib_dump_entry, cur_index)
	cur_index = cur_index + 1
	if cur_index >= fib_dump_entry.num_ether_entries then
		return nil
	end
	return cur_index, fib_dump_entry.ether_tbl[cur_index]
end

-- Iterate the Ethernet entries of a fib_dump_entry.
-- This iterator is meant to be used in a for loop.
function ethernet_entries (fib_dump_entry)
	return ethernet_next, fib_dump_entry, -1
end

-- The following is an example function that can be used as
-- the callback function of list_fib4_entries() and list_fib6_entries().

-- Parameter fib_dump_entry is going to be released after
-- print_fib_dump_entry() returns, so don't keep references to fib_dump_entry
-- or any of the data reachable through its fields.

function print_fib_dump_entry(fib_dump_entry, acc)
	local ip_addr_str

	ip_addr_str = dylib.ip_format_addr(fib_dump_entry.addr)
	acc = acc .. "FIB entry for IP prefix: " .. ip_addr_str ..
		"/" .. fib_dump_entry.prefix_len .. " with action " ..
		tostring(fib_dump_entry.action)

	if fib_dump_entry.action == c.GK_FWD_GRANTOR then
		ip_addr_str = dylib.ip_format_addr(fib_dump_entry.grantor_ip)
		acc = acc .. "\n\tGrantor IP address: " .. ip_addr_str
	end

	acc = acc .. "\n\t#Ethernet cache entries: " ..
		fib_dump_entry.num_ether_entries
	for i, eth_entry in  ethernet_entries(fib_dump_entry) do
		local d_buf = dylib.ether_format_addr(eth_entry.d_addr)
		local stale = eth_entry.stale and "stale" or "fresh"

		ip_addr_str = dylib.ip_format_addr(eth_entry.nexthop_ip)
		acc = acc .. "\n\t\tEther cache entry#" .. (i + 1) ..
			": [state: " .. stale .. ", nexthop ip: " ..
			ip_addr_str .. ", d_addr: " .. d_buf .. "]"
	end

	return acc .. "\n"
end
