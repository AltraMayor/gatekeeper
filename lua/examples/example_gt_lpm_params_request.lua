require "gatekeeper/staticlib"

local dyc = staticlib.c.get_dy_conf()

if dyc.gt == nil then
	return "Gatekeeper: failed to run as Grantor server\n"
end

-- The function assumes that the variable lpm, an IPv4 LPM table,
-- is globally available in the policy as in the policy example.
local function example()
	local max_rules, number_tbl8s = lpmlib.lpm_get_paras(lpm)
	return policylib.c.gt_lcore_id() .. ":" .. max_rules ..
		"," .. number_tbl8s .. "\n"
end

local reply_msg = dylib.update_gt_lua_states_incrementally(
	dyc.gt, example, true)
return "gt: successfully updated the lua states\n" ..
	"The returned message is: " .. reply_msg
