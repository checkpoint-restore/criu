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
RM		:= rm -f
LD		:= ld
CC		:= gcc
ECHO		:= echo
NM		:= nm
AWK		:= awk
SH		:= bash
MAKE		:= make
OBJCOPY		:= objcopy

#
# Fetch ARCH from the uname if not yet set
#
ARCH ?= $(shell uname -m | sed		\
		-e s/i.86/i386/		\
		-e s/sun4u/sparc64/	\
		-e s/arm.*/arm/		\
		-e s/sa110/arm/		\
		-e s/s390x/s390/	\
		-e s/parisc64/parisc/	\
		-e s/ppc.*/powerpc/	\
		-e s/mips.*/mips/	\
		-e s/sh[234].*/sh/)

ifeq ($(ARCH),i386)
	ARCH         := x86-32
	DEFINES      := -DCONFIG_X86_32
endif
ifeq ($(ARCH),x86_64)
	ARCH         := x86
	DEFINES      := -DCONFIG_X86_64
	LDARCH       := i386:x86-64
endif

ifeq ($(ARCH),arm)
	ARCH         := arm
	ARCH_DEFINES := -DCONFIG_ARM
	LDARCH       := arm
	CFLAGS       += -march=armv7-a
endif

SRC_DIR		?= $(CURDIR)
ARCH_DIR	:= arch/$(ARCH)

$(if $(wildcard $(ARCH_DIR)),,$(error "The architecture $(ARCH) isn't supported"))

CFLAGS		+= -Iinclude -Ipie -I. -I$(ARCH_DIR)
CFLAGS		+= -iquote $(ARCH_DIR)/include -fno-strict-aliasing

LIBS		:= -lrt -lpthread -lprotobuf-c

DEFINES		+= -D_FILE_OFFSET_BITS=64
DEFINES		+= -D_GNU_SOURCE

WARNINGS	:= -Wall

ifneq ($(WERROR),0)
	WARNINGS += -Werror
endif

ifeq ($(DEBUG),1)
	DEFINES += -DCR_DEBUG
	CFLAGS	+= -O0 -ggdb3
else
	CFLAGS	+= -O2
endif

CFLAGS		+= $(WARNINGS) $(DEFINES)
SYSCALL-LIB	:= arch/$(ARCH)/syscalls.built-in.o
ARCH-LIB	:= arch/$(ARCH)/crtools.built-in.o

export E Q CC ECHO MAKE CFLAGS LIBS ARCH DEFINES MAKEFLAGS
export SRC_DIR SYSCALL-LIB SH RM ARCH_DIR OBJCOPY LDARCH LD

include scripts/Makefile.version
include scripts/Makefile.rules
#
# shorthand
build := -s -r -R --no-print-directory -f scripts/Makefile.build makefile=Makefile obj

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
OBJS		+= fsnotify.o
OBJS		+= signalfd.o
OBJS		+= pstree.o
OBJS		+= protobuf.o
OBJS		+= tty.o
OBJS		+= cr-exec.o
OBJS		+= cpu.o
OBJS		+= file-lock.o

DEPS		:= $(patsubst %.o,%.d,$(OBJS))

.PHONY: all zdtm test rebuild clean distclean tags cscope	\
	docs help pie protobuf arch/$(ARCH)

ifeq ($(GCOV),1)
%.o $(PROGRAM): override CFLAGS += --coverage
endif

all: pie $(VERSION_HEADER)
	$(Q) $(MAKE) $(PROGRAM)

protobuf/%::
	$(Q) $(MAKE) $(build)=protobuf $@
protobuf:
	$(Q) $(MAKE) $(build)=protobuf all

arch/$(ARCH)/%:: protobuf
	$(Q) $(MAKE) $(build)=arch/$(ARCH) $@
arch/$(ARCH): protobuf
	$(Q) $(MAKE) $(build)=arch/$(ARCH) all

pie/%:: arch/$(ARCH)
	$(Q) $(MAKE) $(build)=pie $@
pie: arch/$(ARCH)
	$(Q) $(MAKE) $(build)=pie all

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

$(PROGRAM): $(SYSCALL-LIB) $(ARCH-LIB) pie/util-net.o protobuf/built-in.o $(OBJS)
	$(E) "  LINK    " $@
	$(Q) $(CC) $(CFLAGS) $^ $(LIBS) -o $@

zdtm: all
	$(Q) $(MAKE) -C test/zdtm all

test: zdtm
	$(Q) $(SH) test/zdtm.sh

rebuild:
	$(E) "  FORCE-REBUILD"
	$(Q) $(RM) ./*.o
	$(Q) $(RM) ./*.d
	$(Q) $(RM) ./protobuf/*.pb-c.c
	$(Q) $(RM) ./protobuf/*.pb-c.h
	$(Q) $(MAKE)

clean:
	$(E) "  CLEAN"
	$(Q) $(RM) $(VERSION_HEADER)
	$(Q) $(MAKE) $(build)=arch/$(ARCH) clean
	$(Q) $(MAKE) $(build)=protobuf clean
	$(Q) $(MAKE) $(build)=pie clean
	$(Q) $(RM) ./*.o
	$(Q) $(RM) ./*.d
	$(Q) $(RM) ./*.i
	$(Q) $(RM) ./*.img
	$(Q) $(RM) ./*.out
	$(Q) $(RM) ./*.bin
	$(Q) $(RM) ./$(PROGRAM)
	$(Q) $(RM) -r ./test/dump/
	$(Q) $(RM) ./*.gcov ./*.gcda ./*.gcno
	$(Q) $(RM) -r ./gcov
	$(Q) $(RM) -r ./test/lib/
	$(Q) $(RM) -r ./test/lib64/
	$(Q) $(MAKE) -C test/zdtm cleandep
	$(Q) $(MAKE) -C test/zdtm clean
	$(Q) $(MAKE) -C test/zdtm cleanout
	$(Q) $(MAKE) -C Documentation clean

distclean: clean
	$(E) "  DISTCLEAN"
	$(Q) $(RM) ./tags
	$(Q) $(RM) ./cscope*

tags:
	$(E) "  GEN" $@
	$(Q) $(RM) tags
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

gcov:
	$(E) " GCOV"
	$(Q) mkdir gcov && \
	cd gcov && \
	cp ../*.gcno ../*.c ../test/root/crtools/	&& \
	geninfo --no-checksum  --output-filename crtools.l.info --no-recursion .. && \
	geninfo --no-checksum  --output-filename crtools.ns.info --no-recursion ../test/root/crtools && \
	sed -i 's#/test/root/crtools##' crtools.ns.info && \
	lcov -a crtools.l.info -a crtools.ns.info -o crtools.info && \
	genhtml -o html crtools.info

deps-targets := $(OBJS) $(patsubst %.o,%.s,$(OBJS)) $(patsubst %.o,%.i,$(OBJS)) $(PROGRAM)

.DEFAULT_GOAL	:= all

ifneq ($(filter $(deps-targets), $(MAKECMDGOALS)),)
	INCDEPS := 1
endif

ifeq ($(INCDEPS),1)
-include $(DEPS)
endif
