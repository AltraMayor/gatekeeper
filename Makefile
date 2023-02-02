# Gatekeeper - DDoS protection system.
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
SRCS-y += gk/main.c gk/rt.c gk/bpf.c
SRCS-y += gt/main.c gt/lua_lpm.c
SRCS-y += lls/main.c lls/cache.c lls/arp.c lls/nd.c
SRCS-y += sol/main.c

# Libraries.
SRCS-y += lib/mailbox.c lib/net.c lib/flow.c lib/ipip.c \
	lib/launch.c lib/lpm.c lib/rib.c lib/fib.c lib/acl.c lib/varip.c \
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
CFLAGS += -O3 -g $(shell $(PKGCONF) --cflags libdpdk) \
	  -DALLOW_EXPERIMENTAL_API -DCORO_ASM \
	  -Wall -Wextra -Wno-packed-not-aligned -Wno-address-of-packed-member \
	  -Wfatal-errors $(WERROR_FLAGS) \
	  -I${GATEKEEPER}include -I/usr/local/include/luajit-2.0/
LDLIBS += $(LDIR) -rdynamic -L/usr/local/lib/ -lluajit-5.1 -ldl \
	-lm -lmnl -lkmod -lcap -lrte_net_bond
LDFLAGS_SHARED := $(shell $(PKGCONF) --libs libdpdk) $(LDLIBS)
LDFLAGS_STATIC := $(shell $(PKGCONF) --static --libs libdpdk) $(LDLIBS)

LINK = $(CC) -o $@ $(OBJS-y) $(LDFLAGS) $(LDFLAGS_STATIC)
COMPILE = $(CC) $(CFLAGS) $(EXTRA_CFLAGS) -MMD -c $< -o $@

$(BUILD_DIR)/$(APP): $(OBJS-y) Makefile $(PC_FILE) | $(BUILD_DIR)
	@echo "LINK\t$@"
	@echo $(LINK) > $@.cc
	@$(LINK)

$(BUILD_DIR)/%.o: %.c
	@echo "CC\t$@"
	@[ -d $(@D) ] || mkdir -p $(@D)
	@echo $(COMPILE) > $(patsubst %.o,%.cc,$@)
	@$(COMPILE)

$(BUILD_DIR):
	@mkdir -p $@

.PHONY: clean
clean:
	rm -rf $(BUILD_DIR)

.PHONY: cscope
cscope:
	cscope -b -R -s.

# Include dependencies on header files.
-include $(DEPS-y)
