LIBDIR	:= .

CFLAGS	+= $(USERCFLAGS)

LIB	:= libzdtmtst.a

LIBSRC	:= datagen.c msg.c parseargs.c test.c streamutil.c lock.c ns.c tcp.c unix.c fs.c sysctl.c mem.c file.c mountinfo.c

PKG_CONFIG ?= pkg-config
pkg-config-check = $(shell sh -c '$(PKG_CONFIG) $(1) && echo y')
ifeq ($(call pkg-config-check,libbpf),y)
LIBSRC	+= bpfmap_zdtm.c
endif

LIBOBJ	:= $(LIBSRC:%.c=%.o)

BIN	:= groups
SRC	:= $(LIBSRC) groups.c
DEP	:= $(SRC:%.c=%.d)
OBJ	:= $(SRC:%.c=%.o)
LDLIBS	:= $(LIB)

TARGETS	:= $(LIB) $(BIN)

include ../Makefile.inc

all:	$(TARGETS)
.PHONY: all

clean-more:
	$(RM) $(TARGETS)
.PHONY: clean-more
clean: clean-more

$(LIB):	$(LIBOBJ)
	$(E) " AR       " $@
	$(Q)ar rcs $@ $^
