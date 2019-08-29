require "gatekeeper/staticlib"

local acc_start = ""
local reply_msg = ""

local dyc = staticlib.c.get_dy_conf()

local ret = dylib.c.add_fib_entry("10.0.3.0/24", "10.0.3.2",
	"10.0.2.2", dylib.c.GK_FWD_GRANTOR, dyc.gk)
if ret < 0 then
	return "gk: failed to add an FIB entry\n"
end

return "gk: successfully processed all the FIB entries\n" .. reply_msg
