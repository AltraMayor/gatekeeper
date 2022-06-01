module("stdcdefs", package.seeall)

--
-- C structs exported through FFI
--

local ffi = require("ffi")

-- Structs
ffi.cdef[[
struct in_addr {
	uint32_t s_addr;
};

struct in6_addr {
	unsigned char s6_addr[16];
};

]]

c = ffi.C
