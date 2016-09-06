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

# XXX This Makefile (in combination with the DPDK Makefiles) does
# not recognize when a file has changed and re-compilation is
# needed -- you need to explicitly do `make clean`. We probably
# need to add a directive to look in the subdirectories.

ifeq ($(RTE_SDK),)
$(error "Please define RTE_SDK environment variable.")
endif

RTE_TARGET ?= x86_64-native-linuxapp-gcc
GATEKEEPER := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

include $(RTE_SDK)/mk/rte.vars.mk

APP = gatekeeper

SRCS-y := main/main.c

# Functional blocks.
SRCS-y += arp/main.c
SRCS-y += bp/main.c
SRCS-y += catcher/main.c
SRCS-y += config/static.c config/dynamic.c
SRCS-y += cps/main.c
SRCS-y += ggu/main.c
SRCS-y += gk/main.c
SRCS-y += gt/main.c
SRCS-y += rt/main.c

# Libraries.
SRCS-y += lib/mailbox.c lib/net.c

CFLAGS += $(WERROR_FLAGS) -I${GATEKEEPER}/include
EXTRA_CFLAGS += -O3 -g -Wfatal-errors

include $(RTE_SDK)/mk/rte.extapp.mk
