require "gatekeeper/staticlib"

local dyc = staticlib.c.get_dy_conf()
if dyc == nil then
	return "No dynamic configuration block available"
end
if dyc.gk == nil then
	return "No GK block available; not a Gatekeeper server"
end

local function new_summary()
	return { actions = {}, prefix_lengths = {} }
end

local function summarize_fib(fib_dump_entry, acc)
	local actions = acc.actions
	-- fib_dump_entry.action is of type enum gk_fib_action,
	-- so it must be casted into a number to avoid having
	-- each instance as a unique value.
	local action = tonumber(fib_dump_entry.action)
	if actions[action] == nil then
		actions[action] = 1
	else
		actions[action] = actions[action] + 1
	end

	local prefix_lengths = acc.prefix_lengths
	local prefix_len = fib_dump_entry.prefix_len
	if prefix_lengths[prefix_len] == nil then
		prefix_lengths[prefix_len] = 1
	else
		prefix_lengths[prefix_len] = prefix_lengths[prefix_len] + 1
	end

	return false, acc
end

local function report_summary(output, summary)
	local total1 = 0
	for action, count in pairs(summary.actions) do
		output[#output + 1] = "\t"
		output[#output + 1] = dylib.fib_action_to_str(action)
		output[#output + 1] = ": "
		output[#output + 1] = tostring(count)
		output[#output + 1] = "\n"
		total1 = total1 + count
	end
	output[#output + 1] = "\n"

	local total2 = 0
	for prefix_length, count in pairs(summary.prefix_lengths) do
		output[#output + 1] = "\t"
		output[#output + 1] = tostring(prefix_length)
		output[#output + 1] = ": "
		output[#output + 1] = tostring(count)
		output[#output + 1] = "\n"
		total2 = total2 + count
	end
	output[#output + 1] = "Total entries: "
	output[#output + 1] = tostring(total2)
	output[#output + 1] = "\n"

	assert(total1 == total2, "Totals are not equal")
end

local output = {}
output[#output + 1] = "IPv4 summary:\n"
report_summary(output, dylib.list_gk_fib4(dyc.gk, summarize_fib, new_summary()))
output[#output + 1] = "\nIPv6 summary:\n"
report_summary(output, dylib.list_gk_fib6(dyc.gk, summarize_fib, new_summary()))
return table.concat(output)
