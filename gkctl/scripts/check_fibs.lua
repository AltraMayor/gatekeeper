require "gatekeeper/staticlib"

local dyc = staticlib.c.get_dy_conf()
if dyc == nil then
	return "No dynamic configuration block available"
end
if dyc.gk == nil then
	return "No GK block available; not a Gatekeeper server"
end

local function new_summary()
	return { dup_fib_ids = {}, present_fib_ids = {} }
end

local function summarize_fib(fib_dump_entry, acc)
	local fib_id = fib_dump_entry.fib_id
	local present_fib_ids = acc.present_fib_ids

	if present_fib_ids[fib_id] == nil then
		present_fib_ids[fib_id] = 1
	else
		present_fib_ids[fib_id] = present_fib_ids[fib_id] + 1
		if present_fib_ids[fib_id] == 2 then
			table.insert(acc.dup_fib_ids, fib_id)
		end
	end

	return false, acc
end

local function report_summary(output, summary)
	table.sort(summary.dup_fib_ids)
	for _, fib_id in ipairs(summary.dup_fib_ids) do
		output[#output + 1] = "\t"
		output[#output + 1] = tostring(fib_id)
		output[#output + 1] = ": "
		output[#output + 1] = tostring(summary.present_fib_ids[fib_id])
		output[#output + 1] = "\n"
	end
end

local output = {}
output[#output + 1] = "IPv4 summary (Duplicate FIB ID: count):\n"
report_summary(output, dylib.list_gk_fib4(dyc.gk, summarize_fib, new_summary()))
output[#output + 1] = "\nIPv6 summary (Duplicate FIB ID: count):\n"
report_summary(output, dylib.list_gk_fib6(dyc.gk, summarize_fib, new_summary()))
return table.concat(output)
