# Gatekeeper - DoS protection system.
# Copyright (C) 2016 Digirati LTDA.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

GATEKEEPER := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
APP := gatekeeper

SRCS-y := main/main.c

# Functional blocks.
SRCS-y += config/static.c config/dynamic.c
SRCS-y += cps/main.c cps/kni.c cps/elf.c cps/rd.c
SRCS-y += ggu/main.c
SRCS-y += gk/main.c gk/fib.c gk/bpf.c
SRCS-y += gt/main.c gt/lua_lpm.c
SRCS-y += lls/main.c lls/cache.c lls/arp.c lls/nd.c
SRCS-y += sol/main.c

# Libraries.
SRCS-y += lib/mailbox.c lib/net.c lib/flow.c lib/ipip.c \
	lib/launch.c lib/lpm.c lib/acl.c lib/varip.c \
	lib/l2.c lib/ratelimit.c lib/memblock.c lib/log_ratelimit.c lib/coro.c

BUILD_DIR := build

OBJS-y := $(SRCS-y:%.c=$(BUILD_DIR)/%.o)
DEPS-y := $(OBJS-y:%.o=%.d)

# Build using pkg-config variables if possible
ifneq ($(shell pkg-config --exists libdpdk && echo 0),0)
$(error "no installation of DPDK found")
endif

PKGCONF ?= pkg-config

PC_FILE := $(shell $(PKGCONF) --path libdpdk 2>/dev/null)
CFLAGS += -O3 $(shell $(PKGCONF) --cflags libdpdk) -DALLOW_EXPERIMENTAL_API -Wno-address-of-packed-member $(WERROR_FLAGS) -I${GATEKEEPER}include -I/usr/local/include/luajit-2.0/
LDLIBS += $(LDIR) -Bstatic -lluajit-5.1 -Bdynamic -lm -lmnl -lkmod -lcap -lrte_net_bond
LDFLAGS_SHARED = $(shell $(PKGCONF) --libs libdpdk) $(LDLIBS)

EXTRA_CFLAGS += -O3 -g -Wfatal-errors -DALLOW_EXPERIMENTAL_API \
	-DCORO_ASM

$(BUILD_DIR)/$(APP): $(OBJS-y) Makefile $(PC_FILE) | $(BUILD_DIR)
	@echo "LINK\t$@"
	@$(CC) -o $@ $(OBJS-y) $(LDFLAGS) $(LDFLAGS_SHARED)

$(BUILD_DIR)/%.o: %.c
	@echo "CC\t$@"
	@[ -d $(@D) ] || mkdir -p $(@D)
	@$(CC) $(CFLAGS) $(EXTRA_CFLAGS) -MMD -c $< -o $@

$(BUILD_DIR):
	@mkdir -p $@

clean:
	rm -rf $(BUILD_DIR)

cscope:
	cscope -b -R -s.
.PHONY: cscope

# Include dependencies on header files.
-include $(DEPS-y)
