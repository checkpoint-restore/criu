include Makefile.inc

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

PROTOBUF-LIB	:= protobuf/protobuf-lib.o

DEPS		:= $(patsubst %.o,%.d,$(OBJS))

MAKEFLAGS	+= --no-print-directory

include Makefile.syscall
include Makefile.pie

.PHONY: all zdtm test rebuild clean distclean tags cscope	\
	docs help pie protobuf

all: pie
	$(Q) $(MAKE) $(PROGRAM)

pie: protobuf
	$(Q) $(MAKE) $(PIE-GEN)

protobuf:
	$(Q) $(MAKE) -C protobuf/

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

$(PROGRAM): $(OBJS) $(SYS-OBJ) $(PROTOBUF-LIB)
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

clean: cleanpie cleansyscall
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
