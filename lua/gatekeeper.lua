module(..., package.seeall)

--
-- Functions to allocate lcores
--

function get_numa_table ()
	local numa_table = {}
	for _, lcore in ipairs(list_lcores()) do
		local socket_id = rte_lcore_to_socket_id(lcore)
		local t = numa_table[socket_id]
		if t == nil then
			numa_table[socket_id] = {lcore}
		else
			table.insert(t, lcore)
		end
	end
	return numa_table
end

function split_array (array, split_pos)
	local a1 = {}
	local a2 = {}
	for i, v in ipairs(array) do
		if i <= split_pos then
			table.insert(a1, v)
		else
			table.insert(a2, v)
		end
	end
	if next(a2) == nil then
		-- a2 is empty.
		a2 = nil
	end
	return a1, a2
end

-- This iterator works like ipairs(), but
--	(1) it skips nil entries instead of stopping, and
--	(2) it starts at index zero instead of one.
function all_ipairs (a)
	return function (last_index, cur_index)
		while true do
			cur_index = cur_index + 1
 			if cur_index > last_index then
				return nil
			end
			local ret = a[cur_index]
			if ret ~= nil then
				return cur_index, ret
			end
		end
	end, table.maxn(a), -1
end

function alloc_lcores_from_same_numa (numa_table, n)
	for numa, lcores in all_ipairs(numa_table) do
		if #lcores >= n then
			local a1, a2 = split_array(lcores, n)
			numa_table[numa] = a2
			return a1
		end
	end
	return nil
end

function alloc_an_lcore (numa_table)
	local lcore_t = alloc_lcores_from_same_numa(numa_table, 1)
	if lcore_t == nil then
		error("There is not enough lcores");
	end
	return lcore_t[1]
end

function print_lcore_array (array)
	io.write("Array: ")
	for i, v in ipairs(array) do
		io.write("[", i, "]=", v, "\t")
	end
	io.write("\n")
end

function print_numa_table (numa_table)
	for numa, lcores in all_ipairs(numa_table) do
		io.write("NUMA ", numa, ":\t")
		for _, lcore in ipairs(lcores) do
			io.write(lcore, "\t")
		end
		io.write("\n")
	end
end
