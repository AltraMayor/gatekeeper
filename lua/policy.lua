local policylib = require("policylib")
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

--[[
The following defines the simple policies without LPM for Grantor.

General format of the simple policies should be:
	IPv4 tables.
	IPv6 tables.

Here, I assume that each group has specific capability parameters,
including speed limit, expiration time, actions - DENY or ACCEPT, etc.
--]]

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
	[255] = default,
}

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
local function lookup_simple_policy(policies, pkt_info)

	local dest_port
	local ph = ffi.cast("struct gt_packet_headers *", pkt_info)

	-- TODO #156 The Lua policy should be responsible for
	-- checking the necessary space for each l4 header type.
	if ph.l4_proto == policylib.c.TCP then
		local tcphdr = ffi.cast("struct tcp_hdr *", fields.l4_hdr)
		dest_port = tcphdr.dst_port
	elseif ph.l4_proto == policylib.c.UDP then
		local udphdr = ffi.cast("struct udp_hdr *", fields.l4_hdr)
		dest_port = udphdr.dst_port
	else
		-- TODO #157 Add support for other transport protocols.
		return nil
	end

	for i, v in ipairs(policies[ph.inner_ip_ver]) do
		for j, g in ipairs(v) do
			if g["dest_port"] == dest_port then
				return g["policy_id"]
			end
		end
	end

	return nil
end

function lookup_policy(pkt_info, policy)
	local ph = ffi.cast("struct gt_packet_headers *",pkt_info)
	local pl = ffi.cast("struct ggu_policy *", policy)

	-- Lookup the simple policy.
	local group = lookup_simple_policy(GLOBAL_POLICIES["simple_policy"], ph)
	if group == nil then group = default end

	pl.state = group["params"]["action"]

	if pl.state == policylib.c.GK_DECLINED then
		pl.params.declined.expire_sec =
			group["params"]["expire_sec"]
	else
		pl.params.granted.tx_rate_kb_sec =
			group["params"]["tx_rate_kb_sec"]
		pl.params.granted.cap_expire_sec =
			group["params"]["cap_expire_sec"]
		pl.params.granted.next_renewal_ms =
			group["params"]["next_renewal_ms"]
		pl.params.granted.renewal_step_ms =
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
	local pl = ffi.cast("struct ggu_policy *", policy)
	pl.state = policylib.c.GK_DECLINED
	pl.params.declined.expire_sec = 600
end
