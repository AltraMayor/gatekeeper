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

struct gk_fib_dump_entry {
	struct ipaddr addr;
	int           prefix_len;
	struct ipaddr grantor_ip;
	bool          stale;
	struct ipaddr nexthop_ip;
	struct ether_addr d_addr;
	enum gk_fib_action action;
};

]]

-- Functions and wrappers
ffi.cdef[[

int add_fib_entry(const char *prefix, const char *gt_ip, const char *gw_ip,
	enum gk_fib_action action, struct gk_config *gk_conf);
int del_fib_entry(const char *ip_prefix, struct gk_config *gk_conf);

]]

c = ffi.C

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
		tostring(fib_dump_entry.action)

	if fib_dump_entry.action == c.GK_FWD_GRANTOR then
		ip_addr_str = dylib.ip_format_addr(fib_dump_entry.grantor_ip)
		acc = acc .. "\n\tGrantor IP address: " .. ip_addr_str
	end

	acc = acc .. "\n\tEthernet cache entry:"

	d_buf = dylib.ether_format_addr(fib_dump_entry.d_addr)
	stale = fib_dump_entry.stale and "stale" or "fresh"
	ip_addr_str = dylib.ip_format_addr(fib_dump_entry.nexthop_ip)
	acc = acc .. ": [state: " .. stale .. ", nexthop ip: " ..
		ip_addr_str .. ", d_addr: " .. d_buf .. "]"

	return acc .. "\n"
end
