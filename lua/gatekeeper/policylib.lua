-- Gatekeeper - DDoS protection system.
-- Copyright (C) 2016 Digirati LTDA.
--
-- This program is free software: you can redistribute it and/or modify
-- it under the terms of the GNU General Public License as published by
-- the Free Software Foundation, either version 3 of the License, or
-- (at your option) any later version.
--
-- This program is distributed in the hope that it will be useful,
-- but WITHOUT ANY WARRANTY; without even the implied warranty of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
-- GNU General Public License for more details.
--
-- You should have received a copy of the GNU General Public License
-- along with this program.  If not, see <http://www.gnu.org/licenses/>.

module(..., package.seeall)

require "gatekeeper/stdcdefs"
require "gatekeeper/lpmlib"

--
-- C functions exported through FFI
--

local ffi = require("ffi")

-- Structs
ffi.cdef[[

enum gk_flow_state { GK_REQUEST, GK_GRANTED, GK_DECLINED, GK_BPF };

enum protocols {
	ICMP = 1,
	TCP = 6,
	UDP = 17,
	ICMPV6 = 58,
	IPV4 = 0x0800,
	IPV6 = 0x86DD,
};

enum icmp_types {
	ICMP_ECHO_REQUEST_TYPE = 8,
};

enum icmp_codes {
	ICMP_ECHO_REQUEST_CODE = 0,
};

enum icmpv6_types {
	ICMPV6_ECHO_REQUEST_TYPE = 128,
};

enum icmpv6_codes {
	ICMPV6_ECHO_REQUEST_CODE = 0,
};

struct rte_ipv4_hdr {
	uint8_t  version_ihl;
	uint8_t  type_of_service;
	uint16_t total_length;
	uint16_t packet_id;
	uint16_t fragment_offset;
	uint8_t  time_to_live;
	uint8_t  next_proto_id;
	uint16_t hdr_checksum;
	uint32_t src_addr;
	uint32_t dst_addr;
} __attribute__((__packed__));

struct rte_ipv6_hdr {
	uint32_t vtc_flow;
	uint16_t payload_len;
	uint8_t  proto; 
	uint8_t  hop_limits;
	uint8_t  src_addr[16];
	uint8_t  dst_addr[16];
} __attribute__((__packed__));

struct rte_tcp_hdr {
	uint16_t src_port;
	uint16_t dst_port;
	uint32_t sent_seq;
	uint32_t recv_ack;
	uint8_t  data_off;
	uint8_t  tcp_flags;
	uint16_t rx_win;
	uint16_t cksum;
	uint16_t tcp_urp;
} __attribute__((__packed__));

struct rte_udp_hdr {
	uint16_t src_port;
	uint16_t dst_port;
	uint16_t dgram_len;
	uint16_t dgram_cksum;
} __attribute__((__packed__));

struct rte_icmp_hdr {
	uint8_t  icmp_type;
	uint8_t  icmp_code;
	uint16_t icmp_cksum;
	uint16_t icmp_ident;
	uint16_t icmp_seq_nb;
} __attribute__((__packed__));

struct icmpv6_hdr {
	uint8_t  icmpv6_type;
	uint8_t  icmpv6_code;
	uint16_t icmpv6_cksum;
} __attribute__((__packed__));

struct gt_packet_headers {
	uint16_t outer_ethertype;
	uint16_t inner_ip_ver;
	uint8_t l4_proto;
	uint8_t priority;
	uint8_t outer_ecn;
	uint16_t upper_len;

	void *l2_hdr;
	void *outer_l3_hdr;
	void *inner_l3_hdr;
	void *l4_hdr;
	bool frag;
	/* This struct has hidden fields. */
};

struct ip_flow {
	uint16_t proto;

	union {
		struct {
			uint32_t src;
			uint32_t dst;
		} v4;

		struct {
			uint8_t src[16];
			uint8_t dst[16];
		} v6;
	} f;
};

struct ggu_granted {
	uint32_t tx_rate_kib_sec;
	uint32_t cap_expire_sec;
	uint32_t next_renewal_ms;
	uint32_t renewal_step_ms;
} __attribute__ ((packed));

struct ggu_declined {
	uint32_t expire_sec;
} __attribute__ ((packed));

struct gk_bpf_cookie {
	uint64_t mem[8];
};

struct ggu_bpf {
	uint32_t expire_sec;
	uint8_t  program_index;
	uint8_t  reserved;
	uint16_t cookie_len;
	struct gk_bpf_cookie cookie;
} __attribute__ ((packed));

struct ggu_policy {
	uint8_t state;
	struct ip_flow flow;
	union {
		struct ggu_granted granted;
		struct ggu_declined declined;
		struct ggu_bpf bpf;
	} params;
};

struct granted_params {
	uint32_t tx_rate_kib_sec;
	uint32_t next_renewal_ms;
	uint32_t renewal_step_ms;
} __attribute__ ((packed));

struct grantedv2_params {
	uint32_t tx1_rate_kib_sec;
	uint32_t tx2_rate_kib_sec;
	uint32_t next_renewal_ms;
	uint32_t renewal_step_ms;
	bool direct_if_possible;
} __attribute__ ((packed));

static const unsigned char TCPSRV_MAX_NUM_PORTS = 12;

struct tcpsrv_ports {
	uint16_t p[TCPSRV_MAX_NUM_PORTS];
};

struct tcpsrv_params {
	uint32_t tx1_rate_kib_sec;
	uint32_t next_renewal_ms;
	uint32_t renewal_step_ms:24;
	uint8_t listening_port_count:4;
	uint8_t remote_port_count:4;
	struct tcpsrv_ports ports;
} __attribute__ ((packed));

uint16_t gt_cpu_to_be_16(uint16_t x);
uint32_t gt_cpu_to_be_32(uint32_t x);
uint16_t gt_be_to_cpu_16(uint16_t x);
uint32_t gt_be_to_cpu_32(uint32_t x);
unsigned int gt_lcore_id(void);

]]

c = ffi.C

BPF_INDEX_GRANTED = 0
BPF_INDEX_DECLINED = 1
BPF_INDEX_GRANTEDV2 = 2
BPF_INDEX_WEB = 3
BPF_INDEX_TCPSRV = 4

function decision_granted_nobpf(policy, tx_rate_kib_sec, cap_expire_sec,
	next_renewal_ms, renewal_step_ms)
	policy.state = c.GK_GRANTED
	policy.params.granted.tx_rate_kib_sec = tx_rate_kib_sec
	policy.params.granted.cap_expire_sec = cap_expire_sec
	policy.params.granted.next_renewal_ms = next_renewal_ms
	policy.params.granted.renewal_step_ms = renewal_step_ms
	return true
end

function decision_declined_nobpf(policy, expire_sec)
	policy.state = c.GK_DECLINED
	policy.params.declined.expire_sec = expire_sec
	return false
end

function decision_granted(policy, tx_rate_kib_sec, cap_expire_sec,
	next_renewal_ms, renewal_step_ms)
	policy.state = c.GK_BPF
	policy.params.bpf.expire_sec = cap_expire_sec
	policy.params.bpf.program_index = BPF_INDEX_GRANTED
	policy.params.bpf.reserved = 0
	policy.params.bpf.cookie_len = ffi.sizeof("struct granted_params")

	local params = ffi.cast("struct granted_params *",
		policy.params.bpf.cookie)
	params.tx_rate_kib_sec = tx_rate_kib_sec
	params.next_renewal_ms = next_renewal_ms
	params.renewal_step_ms = renewal_step_ms

	return true
end

function decision_declined(policy, expire_sec)
	policy.state = c.GK_BPF
	policy.params.bpf.expire_sec = expire_sec
	policy.params.bpf.program_index = BPF_INDEX_DECLINED
	policy.params.bpf.reserved = 0
	policy.params.bpf.cookie_len = 0
	return false
end

function decision_grantedv2_will_full_params(program_index, policy,
	tx1_rate_kib_sec, tx2_rate_kib_sec, cap_expire_sec,
	next_renewal_ms, renewal_step_ms, direct_if_possible)
	policy.state = c.GK_BPF
	policy.params.bpf.expire_sec = cap_expire_sec
	policy.params.bpf.program_index = program_index
	policy.params.bpf.reserved = 0
	policy.params.bpf.cookie_len = ffi.sizeof("struct grantedv2_params")

	local params = ffi.cast("struct grantedv2_params *",
		policy.params.bpf.cookie)
	params.tx1_rate_kib_sec = tx1_rate_kib_sec
	params.tx2_rate_kib_sec = tx2_rate_kib_sec
	params.next_renewal_ms = next_renewal_ms
	params.renewal_step_ms = renewal_step_ms
	params.direct_if_possible = direct_if_possible

	return true
end

local function ipairs_skip_first(a)
	local f, t, i = ipairs(a)
	return f, t, i + 1
end

local function sort_unique(array)
	if #array < 2 then
		return
	end

	table.sort(array)

	-- Unique
	local prv_indx = 1
	local prv_elem = array[prv_indx]
	for i, v in ipairs_skip_first(array) do
		if prv_elem ~= v then
			prv_indx = prv_indx + 1
			prv_elem = v
			array[prv_indx] = prv_elem
		end
		if prv_indx < i then
			array[i] = nil
		end
	end
end

-- CAUTION: Do not refer to the arrays @listening_ports and @remote_ports
-- once this function returns.
function tcpsrv_ports(listening_ports, remote_ports)
	sort_unique(listening_ports)
	sort_unique(remote_ports)

	local total_ports = #listening_ports + #remote_ports
	if total_ports > c.TCPSRV_MAX_NUM_PORTS then
		error("There are " .. total_ports .. " ports; maximum of "  ..
			c.TCPSRV_MAX_NUM_PORTS .. " ports")
	end

	local ret = {
		listening_port_count = #listening_ports,
		remote_port_count = #remote_ports,
		ports = listening_ports,
	}

	-- Padding.
	local pad_n = c.TCPSRV_MAX_NUM_PORTS - total_ports
	for i = 1, pad_n do
		table.insert(ret.ports, 0)
	end

	-- Add remote ports in reverse order.
	for i = #remote_ports, 1, -1 do
		table.insert(ret.ports, remote_ports[i])
	end

	assert(#ret.ports == c.TCPSRV_MAX_NUM_PORTS)
	return ret
end

-- The BPF tcp-services.c only supports 12 (listening + remote) ports.
-- The BPF tcp-services.c does not support idiosyncratic services like FTP.
-- If you need more than 12 ports, or supporting idiosyncratic services,
-- write a custom BPF following the BPF web.c example.
function decision_tcpsrv(policy, tx1_rate_kib_sec, cap_expire_sec,
	next_renewal_ms, renewal_step_ms, ports)
	policy.state = c.GK_BPF
	policy.params.bpf.expire_sec = cap_expire_sec
	policy.params.bpf.program_index = BPF_INDEX_TCPSRV
	policy.params.bpf.reserved = 0
	policy.params.bpf.cookie_len = ffi.sizeof("struct tcpsrv_params")

	local params = ffi.cast("struct tcpsrv_params *",
		policy.params.bpf.cookie)
	params.tx1_rate_kib_sec = tx1_rate_kib_sec
	params.next_renewal_ms = next_renewal_ms
	params.renewal_step_ms = renewal_step_ms
	params.listening_port_count = ports.listening_port_count
	params.remote_port_count = ports.remote_port_count

	for i, v in ipairs(ports.ports) do
		params.ports.p[i - 1] = v
	end

	return true
end

-- The prototype of this function is compatible with decision_granted() to
-- help testing it. Policies may prefer to call
-- decision_grantedv2_will_full_params() instead.
function decision_grantedv2(policy, tx_rate_kib_sec, cap_expire_sec,
	next_renewal_ms, renewal_step_ms)
	return decision_grantedv2_will_full_params(BPF_INDEX_GRANTEDV2,
		policy, tx_rate_kib_sec, tx_rate_kib_sec * 0.05, -- 5%
		cap_expire_sec, next_renewal_ms, renewal_step_ms, false)
end

-- The prototype of this function is compatible with decision_granted() to
-- help testing it. Policies may prefer to call
-- decision_grantedv2_will_full_params() instead.
function decision_web(policy, tx_rate_kib_sec, cap_expire_sec,
	next_renewal_ms, renewal_step_ms)
	return decision_grantedv2_will_full_params(BPF_INDEX_WEB,
		policy, tx_rate_kib_sec, tx_rate_kib_sec * 0.05, -- 5%
		cap_expire_sec, next_renewal_ms, renewal_step_ms, false)
end

-- There is no -> operator in Lua. The . operator works
-- equivalently for accessing members of a struct AND
-- accessing members of a struct through a reference.
-- Therefore, the arguments to this function can be of type
-- struct in6_addr or struct in6_addr &.
function ipv6_addrs_equal(addr1, addr2)
	for i=0,15 do
		if addr1.s6_addr[i] ~= addr2.s6_addr[i] then
			return false
		end
	end
	return true
end
