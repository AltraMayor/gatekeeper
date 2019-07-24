CC = clang
CFLAGS += -O2 -target bpf -I../include \
	  -I$(RTE_SDK)/$(RTE_TARGET)/include \
	  -Wno-int-to-void-pointer-cast

TARGETS = granted.bpf declined.bpf

DESTDIR ?= "../lua/bpf"
INSTALL = install

all: $(TARGETS)

copy: all
	$(INSTALL) -d $(DESTDIR)
	$(INSTALL) -m660 $(TARGETS) $(DESTDIR)

%.bpf: %.c
	$(CC) $(CFLAGS) -o $@ -c $^

PHONY: cscope clean

cscope:
	cscope -b *.c *.h

clean:
	rm -f cscope.out $(TARGETS)
