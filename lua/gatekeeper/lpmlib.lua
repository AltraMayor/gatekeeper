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

function lpm6_add_tbl8s(ip6_addr, prefix_len, prefixes)
	local depth = 24
	local ret = 0

	-- For a prefix with length longer than 24, one tbl8
	-- is needed every 8 bits. If the prefix length is not
	-- a multiple of 8, then prefix expansion will be performed
	-- on that tbl8 entry. More details can be found on
	-- the addition description in DPDK LPM6 library:
	-- https://doc.dpdk.org/guides/prog_guide/lpm6_lib.html#addition
	while depth < prefix_len do
		local prefix = lpmlib.ip6_mask_addr(ip6_addr, depth)
			.. "/" .. depth
		if not prefixes[prefix] then
			prefixes[prefix] = true
			ret = ret + 1
		end

		depth = depth + 8
	end

	return ret
end
