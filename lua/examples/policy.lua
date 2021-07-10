local policylib = require("gatekeeper/policylib")
local ffi = require("ffi")

local function dcs_default(policy)
	return policylib.decision_granted(policy,
		1024,	-- tx_rate_kib_sec
		300,	-- cap_expire_sec
		240000,	-- next_renewal_ms
		3000)	-- renewal_step_ms
end

local function dcs_malformed(policy)
	return policylib.decision_declined(policy, 10)
end

local function dcs_declined(policy)
	return policylib.decision_declined(policy, 60)
end

local function dcs_friendly(policy)
	return policylib.decision_granted(policy,
		2048,	-- tx_rate_kib_sec
		600,	-- cap_expire_sec
		540000,	-- next_renewal_ms
		3000)	-- renewal_step_ms
end

local groups = {
	[1] = dcs_friendly,
	[253] = dcs_declined,
	[254] = dcs_malformed,
	[255] = dcs_default,
}

-- The following defines simple policies without a LPM table.
local simple_policy = {
	[policylib.c.IPV4] = {
		-- Loosely assume that TCP and UDP ports are equivalents
		-- to simplify this example.
		[policylib.c.gt_cpu_to_be_16(80)] = dcs_friendly,
	},
	[policylib.c.IPV6] = {
		-- Loosely assume that TCP and UDP ports are equivalents
		-- to simplify this example.
		[policylib.c.gt_cpu_to_be_16(80)] = dcs_friendly,
	},
}

-- Function that looks up the simple policy for the packet.
local function lookup_simple_policy(pkt_info)

	if pkt_info.frag then
		return dcs_malformed
	end

	if pkt_info.inner_ip_ver == policylib.c.IPV4 and
			pkt_info.l4_proto == policylib.c.ICMP then
		if pkt_info.upper_len < ffi.sizeof("struct rte_icmp_hdr") then
			return dcs_malformed
		end

		local ipv4_hdr = ffi.cast("struct rte_ipv4_hdr *",
			pkt_info.inner_l3_hdr)
		local icmp_hdr = ffi.cast("struct rte_icmp_hdr *",
			pkt_info.l4_hdr)
		local icmp_type = icmp_hdr.icmp_type
		local icmp_code = icmp_hdr.icmp_code

		-- Disable traceroute through ICMP into network.
		if ipv4_hdr.time_to_live < 16 and icmp_type ==
				policylib.c.ICMP_ECHO_REQUEST_TYPE and
				icmp_code ==
				policylib.c.ICMP_ECHO_REQUEST_CODE then
			return dcs_declined
		end

		return dcs_default
	end

	if pkt_info.inner_ip_ver == policylib.c.IPV6 and
			pkt_info.l4_proto == policylib.c.ICMPV6 then
		if pkt_info.upper_len < ffi.sizeof("struct icmpv6_hdr") then
			return dcs_malformed
		end

		local ipv6_hdr = ffi.cast("struct rte_ipv6_hdr *",
			pkt_info.inner_l3_hdr)
		local icmpv6_hdr = ffi.cast("struct icmpv6_hdr *",
			pkt_info.l4_hdr)
		local icmpv6_type = icmpv6_hdr.icmpv6_type
		local icmpv6_code = icmpv6_hdr.icmpv6_code

		-- Disable traceroute through ICMPV6 into network.
		if ipv6_hdr.hop_limits < 16 and icmpv6_type ==
				policylib.c.ICMPV6_ECHO_REQUEST_TYPE and
				icmpv6_code ==
				policylib.c.ICMPV6_ECHO_REQUEST_CODE then
			return dcs_declined
		end

		return dcs_default
	end

	local l3_policy = simple_policy[pkt_info.inner_ip_ver]
	if l3_policy == nil then
		return nil
	end

	if pkt_info.l4_proto == policylib.c.TCP then
		if pkt_info.upper_len < ffi.sizeof("struct rte_tcp_hdr") then
			return dcs_malformed
		end

		local tcphdr = ffi.cast("struct rte_tcp_hdr *", pkt_info.l4_hdr)
		return l3_policy[tcphdr.dst_port]
	end

	if pkt_info.l4_proto == policylib.c.UDP then
		if pkt_info.upper_len < ffi.sizeof("struct rte_udp_hdr") then
			return dcs_malformed
		end

		local udphdr = ffi.cast("struct rte_udp_hdr *", pkt_info.l4_hdr)
		return l3_policy[udphdr.dst_port]
	end

	return nil
end

-- The following defines the LPM policies.

local scaling_factor_rules = 2
local scaling_factor_tbl8s = 2

-- Estimate the number of rules and number of tbl8s in DPDK LPM library.
local function lpm_para_estimate(ipv4_file)
	local num_rules = 0
	local num_tbl8s = 0
	local prefixes = {}

	for line in io.lines(ipv4_file) do
		local ip_addr, prefix_len = lpmlib.str_to_prefix(line)
		num_rules = num_rules + 1
		num_tbl8s = num_tbl8s +
			lpmlib.lpm_add_tbl8s(ip_addr, prefix_len, prefixes)
	end

	return num_rules, num_tbl8s
end

-- Estimate the number of rules and number of tbl8s in DPDK LPM6 library.
local function lpm6_para_estimate(ipv6_file)
	local num_rules = 0
	local num_tbl8s = 0
	local prefixes = {}

	for line in io.lines(ipv6_file) do
		local ip6_addr, prefix_len = lpmlib.str_to_prefix6(line)
		num_rules = num_rules + 1
		num_tbl8s = num_tbl8s +
			lpmlib.lpm6_add_tbl8s(ip6_addr, prefix_len, prefixes)
	end

	return num_rules, num_tbl8s
end

-- This file only contains an example set of Bogons IPv4 lists
-- downloaded from http://www.team-cymru.org/Services/Bogons/fullbogons-ipv4.txt
local bogons_ipv4_file = "lua/examples/bogons-ipv4.txt"
local num_ipv4_rules, num_ipv4_tbl8s = lpm_para_estimate(bogons_ipv4_file)
num_ipv4_rules = math.max(1, scaling_factor_rules * num_ipv4_rules)
num_ipv4_tbl8s = math.max(1, scaling_factor_tbl8s * num_ipv4_tbl8s)
-- This variable is made global, so that the example() function in
-- lua/examples/example_gt_lpm_params_request.lua can access it.
lpm = lpmlib.new_lpm(num_ipv4_rules, num_ipv4_tbl8s)

-- This file only contains an example set of Bogons IPv6 lists
-- downloaded from http://www.team-cymru.org/Services/Bogons/fullbogons-ipv6.txt
local bogons_ipv6_file = "lua/examples/bogons-ipv6.txt"
local num_ipv6_rules, num_ipv6_tbl8s = lpm6_para_estimate(bogons_ipv6_file)
num_ipv6_rules = math.max(1, scaling_factor_rules * num_ipv6_rules)
num_ipv6_tbl8s = math.max(1, scaling_factor_tbl8s * num_ipv6_tbl8s)
local lpm6 = lpmlib.new_lpm6(num_ipv6_rules, num_ipv6_tbl8s)

for line in io.lines(bogons_ipv4_file) do
	local ip_addr, prefix_len = lpmlib.str_to_prefix(line)
	lpmlib.lpm_add(lpm, ip_addr, prefix_len, 253)
end

for line in io.lines(bogons_ipv6_file) do
	local ip_addr, prefix_len = lpmlib.str_to_prefix6(line)
	lpmlib.lpm6_add(lpm6, ip_addr, prefix_len, 253)
end

-- Example global IP addresses for special cases in policy.
ipv6_addr_ex, _ = lpmlib.str_to_prefix6("2001:219::1/128")
ipv4_addr_ex, _ = lpmlib.str_to_prefix("41.78.176.1/32")

local function lookup_lpm_policy(pkt_info)

	if pkt_info.inner_ip_ver == policylib.c.IPV4 then
		local ipv4_hdr = ffi.cast("struct rte_ipv4_hdr *",
			pkt_info.inner_l3_hdr)

		if ipv4_hdr.dst_addr == ipv4_addr_ex then
			return nil
		end

		local policy_id = lpmlib.lpm_lookup(lpm, ipv4_hdr.src_addr)
		if policy_id < 0 then
			return nil
		end

		return groups[policy_id]
	end

	if pkt_info.inner_ip_ver == policylib.c.IPV6 then
		local ipv6_hdr = ffi.cast("struct rte_ipv6_hdr *",
			pkt_info.inner_l3_hdr)

		local dst_addr = ffi.cast("struct in6_addr &",
			ipv6_hdr.dst_addr)
		if policylib.ipv6_addrs_equal(dst_addr, ipv6_addr_ex) then
			return nil
		end

		local src_addr = ffi.cast("struct in6_addr &",
			ipv6_hdr.src_addr)
		local policy_id = lpmlib.lpm6_lookup(lpm6, src_addr)
		if policy_id < 0 then
			return nil
		end

		return groups[policy_id]
	end

	return nil
end

function lookup_policy(pkt_info, policy)

	local group

	group = lookup_lpm_policy(pkt_info)

	if group == nil then
		group = lookup_simple_policy(pkt_info)
	end

	if group == nil then
		group = dcs_default
	end

	return group(policy)
end

--[[
Flows associated with fragments that have to be discarded
before being fully assembled must be punished. Otherwise, an
attacker could overflow the request channel with fragments that
never complete, and policies wouldn't be able to do anything about it
because they would not be aware of these fragments. The punishment
is essentially a policy decision stated in the configuration files
to be applied to these cases. For example, decline the flow for 10 minutes.
--]]
function lookup_frag_punish_policy(policy)
	return policylib.decision_declined(policy, 600)
end
