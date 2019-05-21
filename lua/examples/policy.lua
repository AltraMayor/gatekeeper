local policylib = require("gatekeeper/policylib")
local ffi = require("ffi")

GLOBAL_POLICIES = {}

local default = {
	["params"] = {
		["tx_rate_kb_sec"] = 10,
		["cap_expire_sec"] = 10,
		["next_renewal_ms"] = 10,
		["renewal_step_ms"] = 10,
		["action"] = policylib.c.GK_GRANTED,
	},
}

local malformed = {
	["params"] = {
		["expire_sec"] = 10,
		["action"] = policylib.c.GK_DECLINED,
	},
}

local declined = {
	["params"] = {
		["expire_sec"] = 60,
		["action"] = policylib.c.GK_DECLINED,
	},
}

local IPV4 = policylib.c.IPV4

local group1 = {
	["params"] = {
		["tx_rate_kb_sec"] = 20,
		["cap_expire_sec"] = 20,
		["next_renewal_ms"] = 20,
		["renewal_step_ms"] = 20,
		["action"] = policylib.c.GK_GRANTED,
	},
}

local groups = {
	[1] = group1,
	[253] = declined,
	[254] = malformed,
	[255] = default,
}

--[[
The following defines the simple policies without LPM for Grantor.
General format of the simple policies should be:
	IPv4 tables.
	IPv6 tables.
Here, I assume that each group has specific capability parameters,
including speed limit, expiration time, actions - DENY or ACCEPT, etc.
--]]

local simple_policies = {
	[IPV4] = {
		{
			{
				["dest_port"] = 80,
				["policy_id"] = groups[1],
			},
		},
	},
}

GLOBAL_POLICIES["simple_policy"] = simple_policies

-- Function that looks up the simple policy for the packet.
local function lookup_simple_policy(simple_policy, pkt_info)

	local dest_port

	if pkt_info.l4_proto == policylib.c.TCP then
		if pkt_info.upper_len < ffi.sizeof("struct tcp_hdr") then
			return malformed
		end

		local tcphdr = ffi.cast("struct tcp_hdr *", pkt_info.l4_hdr)
		dest_port = tcphdr.dst_port
	elseif pkt_info.l4_proto == policylib.c.UDP then
		if pkt_info.upper_len < ffi.sizeof("struct udp_hdr") then
			return malformed
		end

		local udphdr = ffi.cast("struct udp_hdr *", pkt_info.l4_hdr)
		dest_port = udphdr.dst_port
	elseif pkt_info.inner_ip_ver == policylib.c.IPV4 and
			pkt_info.l4_proto == policylib.c.ICMP then
		if pkt_info.upper_len < ffi.sizeof("struct icmp_hdr") then
			return malformed
		end

		local ipv4_hdr = ffi.cast("struct ipv4_hdr *",
			pkt_info.inner_l3_hdr)
		local icmp_hdr = ffi.cast("struct icmp_hdr *", pkt_info.l4_hdr)
		local icmp_type = icmp_hdr.icmp_type
		local icmp_code = icmp_hdr.icmp_code

		-- Disable traceroute through ICMP into network.
		if ipv4_hdr.time_to_live < 16 and icmp_type ==
				policylib.c.ICMP_ECHO_REQUEST_TYPE and
				icmp_code ==
				policylib.c.ICMP_ECHO_REQUEST_CODE then
			return declined
		end

		return default
	elseif pkt_info.inner_ip_ver == policylib.c.IPV6 and
			pkt_info.l4_proto == policylib.c.ICMPV6 then
		if pkt_info.upper_len < ffi.sizeof("struct icmpv6_hdr") then
			return malformed
		end

		local ipv6_hdr = ffi.cast("struct ipv6_hdr *",
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
			return declined
		end

		return default
	else
		return nil
	end

	for i, v in ipairs(simple_policy[pkt_info.inner_ip_ver]) do
		for j, g in ipairs(v) do
			if g["dest_port"] == dest_port then
				return g["policy_id"]
			end
		end
	end

	return nil
end

-- The following defines the LPM policies for Grantor.

-- This file only contains an example set of Bogons IPv4 lists
-- downloaded from http://www.team-cymru.org/Services/Bogons/fullbogons-ipv4.txt
local bogons_ipv4_file = "lua/examples/bogons-ipv4.txt"
local lpm = lpmlib.new_lpm(1024, 256)

-- This file only contains an example set of Bogons IPv6 lists
-- downloaded from http://www.team-cymru.org/Services/Bogons/fullbogons-ipv6.txt
local bogons_ipv6_file = "lua/examples/bogons-ipv6.txt"
local lpm6 = lpmlib.new_lpm6(1024, 65536)

for line in io.lines(bogons_ipv4_file) do
	local ip_addr, prefix_len = lpmlib.str_to_prefix(line)
	lpmlib.lpm_add(lpm, ip_addr, prefix_len, 253)
end

for line in io.lines(bogons_ipv6_file) do
	local ip_addr, prefix_len = lpmlib.str_to_prefix6(line)
	lpmlib.lpm6_add(lpm6, ip_addr, prefix_len, 253)
end

-- Function that looks up the lpm policy for the packet.
local function lookup_lpm_policy(lpm_handler, pkt_info)

	if pkt_info.inner_ip_ver == policylib.c.IPV4 then
		local ipv4_hdr = ffi.cast("struct ipv4_hdr *",
			pkt_info.inner_l3_hdr)
		local policy_id = lpmlib.lpm_lookup(lpm_handler,
			ipv4_hdr.src_addr)
		if policy_id < 0 then
			return nil
		end

		return groups[policy_id]
	end

	if pkt_info.inner_ip_ver == policylib.c.IPV6 then
		local ipv6_hdr = ffi.cast("struct ipv6_hdr *",
			pkt_info.inner_l3_hdr)
		local src_addr = ffi.cast("struct in6_addr *",
			ipv6_hdr.src_addr)
		local policy_id = lpmlib.lpm6_lookup(lpm_handler, src_addr)
		if policy_id < 0 then
			return nil
		end

		return groups[policy_id]
	end

	return nil
end

function lookup_policy(pkt_info, policy)

	local group

	-- Lookup the lpm policy.
	if pkt_info.inner_ip_ver == policylib.c.IPV4 then
		group = lookup_lpm_policy(lpm, pkt_info)
	elseif pkt_info.inner_ip_ver == policylib.c.IPV6 then
		group = lookup_lpm_policy(lpm6, pkt_info)
	end

	if group == nil then
		-- Lookup the simple policy.
		group = lookup_simple_policy(
			GLOBAL_POLICIES["simple_policy"], pkt_info)
	end

	if group == nil then
		group = default
	end

	policy.state = group["params"]["action"]

	if policy.state == policylib.c.GK_DECLINED then
		policy.params.declined.expire_sec =
			group["params"]["expire_sec"]
	else
		policy.params.granted.tx_rate_kb_sec =
			group["params"]["tx_rate_kb_sec"]
		policy.params.granted.cap_expire_sec =
			group["params"]["cap_expire_sec"]
		policy.params.granted.next_renewal_ms =
			group["params"]["next_renewal_ms"]
		policy.params.granted.renewal_step_ms =
			group["params"]["renewal_step_ms"]
	end
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
	policy.state = policylib.c.GK_DECLINED
	policy.params.declined.expire_sec = 600
end
