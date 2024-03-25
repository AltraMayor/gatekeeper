CC = clang
CFLAGS += -O2 -g -target bpf -I../include \
	  -Wall -Wextra -Wno-int-to-void-pointer-cast

TARGETS = granted.bpf declined.bpf grantedv2.bpf web.bpf tcp-services.bpf

DESTDIR ?= "../lua/bpf"
INSTALL = install

all: $(TARGETS)

copy: all
	$(INSTALL) -d $(DESTDIR)
	$(INSTALL) -m660 $(TARGETS) $(DESTDIR)

%.bpf: %.c
	$(CC) $(CFLAGS) -o $@ -D RTE_FORCE_INTRINSICS -c $^

PHONY: cscope clean

cscope:
	cscope -b *.c *.h

clean:
	rm -f cscope.out $(TARGETS)
