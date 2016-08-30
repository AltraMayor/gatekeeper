# XXX This Makefile (in combination with the DPDK Makefiles) does
# not recognize when a file has changed and re-compilation is
# needed -- you need to explicitly do `make clean`. We probably
# need to add a directive to look in the subdirectories.

ifeq ($(RTE_SDK),)
$(error "Please define RTE_SDK environment variable.")
endif

RTE_TARGET ?= x86_64-native-linuxapp-gcc

include $(RTE_SDK)/mk/rte.vars.mk

APP = gatekeeper

SRCS-y := main/main.c

CFLAGS += $(WERROR_FLAGS)
EXTRA_CFLAGS += -O3 -g -Wfatal-errors

include $(RTE_SDK)/mk/rte.extapp.mk
