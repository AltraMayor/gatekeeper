module("lpmlib", package.seeall)

function lpm_add_tbl8s(ip_addr, prefix_len, prefixes)
	local masked_ip

	if prefix_len <= 24 then
		return 0
	end

	-- For a prefix with length longer than 24, one tbl8
	-- is needed according to the addition description in
	-- DPDK LPM library:
	-- https://doc.dpdk.org/guides/prog_guide/lpm_lib.html#addition
	masked_ip = lpmlib.ip_mask_addr(ip_addr, 24)
	if prefixes[masked_ip] then
		return 0
	end

	prefixes[masked_ip] = true
	return 1
end

