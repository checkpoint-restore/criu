#
# Common definitions
#

ifeq ($(strip $(V)),)
	E = @echo
	Q = @
else
	E = @\#
	Q =
endif

FIND		:= find
CSCOPE		:= cscope
TAGS		:= ctags
RM		:= rm
LD		:= ld
HEXDUMP		:= hexdump
CC		:= gcc
ECHO		:= echo
NM		:= nm
AWK		:= awk
SH		:= sh
MAKE		:= make

# Additional ARCH settings for x86
ARCH ?= $(shell echo $(uname_M) | sed -e s/i.86/i386/ -e s/sun4u/sparc64/ \
                  -e s/arm.*/arm/ -e s/sa110/arm/ \
                  -e s/s390x/s390/ -e s/parisc64/parisc/ \
                  -e s/ppc.*/powerpc/ -e s/mips.*/mips/ \
                  -e s/sh[234].*/sh/ )

uname_M      := $(shell uname -m | sed -e s/i.86/i386/)
ifeq ($(uname_M),i386)
	ARCH         := x86
	DEFINES      := -DCONFIG_X86_32
endif
ifeq ($(uname_M),x86_64)
	ARCH         := x86
	DEFINES      := -DCONFIG_X86_64
endif

SRC_DIR		?= $(shell pwd)

CFLAGS		= -I$(SRC_DIR)/include -I$(SRC_DIR)/pie -fno-strict-aliasing

LIBS		:= -lrt -lpthread -lprotobuf-c

DEFINES		+= -D_FILE_OFFSET_BITS=64
DEFINES		+= -D_GNU_SOURCE

WARNINGS	:= -Wall

ifneq ($(WERROR),0)
	WARNINGS += -Werror
endif

ifeq ($(DEBUG),1)
	DEFINES += -DCR_DEBUG
endif

ifeq ($(DEBUG),1)
	DEFINES += -DCR_DEBUG
	CFLAGS	+= -O0 -ggdb3
else
	CFLAGS	+= -O2
endif

CFLAGS		+= $(WARNINGS) $(DEFINES)
SYSCALL-LIB	= $(SRC_DIR)/arch/$(ARCH)/syscalls.o
PROTOBUF-LIB	= $(SRC_DIR)/protobuf/protobuf-lib.o

export E Q CC ECHO MAKE CFLAGS LIBS ARCH DEFINES MAKEFLAGS SRC_DIR SYSCALL-LIB SH


PROGRAM		:= crtools

OBJS		+= parasite-syscall.o
OBJS		+= cr-restore.o
OBJS		+= crtools.o
OBJS		+= image.o
OBJS		+= net.o
OBJS		+= proc_parse.o
OBJS		+= cr-dump.o
OBJS		+= cr-show.o
OBJS		+= cr-check.o
OBJS		+= util.o
OBJS		+= util-net.o
OBJS		+= sysctl.o
OBJS		+= ptrace.o
OBJS		+= kcmp-ids.o
OBJS		+= rbtree.o
OBJS		+= log.o
OBJS		+= libnetlink.o
OBJS		+= sockets.o
OBJS		+= sk-inet.o
OBJS		+= sk-tcp.o
OBJS		+= sk-unix.o
OBJS		+= sk-packet.o
OBJS		+= sk-queue.o
OBJS		+= files.o
OBJS		+= files-reg.o
OBJS		+= pipes.o
OBJS		+= fifo.o
OBJS		+= file-ids.o
OBJS		+= namespaces.o
OBJS		+= uts_ns.o
OBJS		+= ipc_ns.o
OBJS		+= netfilter.o
OBJS		+= shmem.o
OBJS		+= eventfd.o
OBJS		+= eventpoll.o
OBJS		+= mount.o
OBJS		+= inotify.o
OBJS		+= signalfd.o
OBJS		+= pstree.o
OBJS		+= protobuf.o
OBJS		+= tty.o

DEPS		:= $(patsubst %.o,%.d,$(OBJS))

.PHONY: all zdtm test rebuild clean distclean tags cscope	\
	docs help pie protobuf x86

all: pie
	$(Q) $(MAKE) $(PROGRAM)

pie: protobuf $(ARCH)
	$(Q) $(MAKE) -C pie/

protobuf:
	$(Q) $(MAKE) -C protobuf/

x86:
	$(Q) $(MAKE) -C arch/x86/

%.o: %.c
	$(E) "  CC      " $@
	$(Q) $(CC) -c $(CFLAGS) $< -o $@

%.i: %.c
	$(E) "  CC      " $@
	$(Q) $(CC) -E $(CFLAGS) $< -o $@

%.s: %.c
	$(E) "  CC      " $@
	$(Q) $(CC) -S $(CFLAGS) -fverbose-asm $< -o $@

%.d: %.c
	$(E) "  DEP     " $@
	$(Q) $(CC) -M -MT $@ -MT $(patsubst %.d,%.o,$@) $(CFLAGS) $< -o $@

$(PROGRAM): $(OBJS) $(SYSCALL-LIB) $(PROTOBUF-LIB)
	$(E) "  LINK    " $@
	$(Q) $(CC) $(CFLAGS) $^ $(LIBS) -o $@

zdtm: all
	$(Q) $(MAKE) -C test/zdtm all

test: zdtm
	$(Q) $(SH) test/zdtm.sh

rebuild:
	$(E) "  FORCE-REBUILD"
	$(Q) $(RM) -f ./*.o
	$(Q) $(RM) -f ./*.d
	$(Q) $(RM) -f ./protobuf/*.pb-c.c
	$(Q) $(RM) -f ./protobuf/*.pb-c.h
	$(Q) $(MAKE)

clean:
	$(E) "  CLEAN"
	$(Q) $(RM) -f ./*.o
	$(Q) $(RM) -f ./*.d
	$(Q) $(RM) -f ./*.i
	$(Q) $(RM) -f ./*.img
	$(Q) $(RM) -f ./*.out
	$(Q) $(RM) -f ./*.bin
	$(Q) $(RM) -f ./$(PROGRAM)
	$(Q) $(RM) -rf ./test/dump/
	$(Q) $(MAKE) -C protobuf/ clean
	$(Q) $(MAKE) -C arch/x86/ clean
	$(Q) $(MAKE) -C pie/ clean
	$(Q) $(MAKE) -C test/zdtm cleandep
	$(Q) $(MAKE) -C test/zdtm clean
	$(Q) $(MAKE) -C test/zdtm cleanout
	$(Q) $(MAKE) -C Documentation clean

distclean: clean
	$(E) "  DISTCLEAN"
	$(Q) $(RM) -f ./tags
	$(Q) $(RM) -f ./cscope*

tags:
	$(E) "  GEN" $@
	$(Q) $(RM) -f tags
	$(Q) $(FIND) . -name '*.[hcS]' ! -path './.*' -print | xargs ctags -a

cscope:
	$(E) "  GEN" $@
	$(Q) $(FIND) . -name '*.[hcS]' ! -path './.*' -print > cscope.files
	$(Q) $(CSCOPE) -bkqu

docs:
	$(Q) $(MAKE) -s -C Documentation all

help:
	$(E) '    Targets:'
	$(E) '      all             - Build all [*] targets'
	$(E) '    * crtools         - Build crtools'
	$(E) '      zdtm            - Build zdtm test-suite'
	$(E) '      docs            - Build documentation'
	$(E) '      clean           - Clean everything'
	$(E) '      tags            - Generate tags file (ctags)'
	$(E) '      cscope          - Generate cscope database'
	$(E) '      rebuild         - Force-rebuild of [*] targets'
	$(E) '      test            - Run zdtm test-suite'

deps-targets := $(OBJS) $(patsubst %.o,%.s,$(OBJS)) $(patsubst %.o,%.i,$(OBJS)) $(PROGRAM)

.DEFAULT_GOAL	:= all

ifneq ($(filter $(deps-targets), $(MAKECMDGOALS)),)
	INCDEPS := 1
endif

ifeq ($(INCDEPS),1)
-include $(DEPS)
endif
