-include Makefile.inc

CFLAGS		+= -I./include
CFLAGS		+= -O0 -ggdb3

LIBS		+= -lrt -lpthread

DEFINES		+= -D_FILE_OFFSET_BITS=64
DEFINES		+= -D_GNU_SOURCE

ifneq ($(WERROR),0)
	WARNINGS += -Werror
endif

ifeq ($(DEBUG),1)
	DEFINES += -DCR_DEBUG
endif

WARNINGS	+= -Wall -Wno-unused
CFLAGS		+= $(WARNINGS) $(DEFINES)

PROGRAM		:= crtools

export CC ECHO MAKE CFLAGS LIBS ARCH DEFINES

OBJS		+= parasite-syscall.o
OBJS		+= cr-restore.o
OBJS		+= crtools.o
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
OBJS		+= sk-queue.o
OBJS		+= files.o
OBJS		+= pipes.o
OBJS		+= file-ids.o
OBJS		+= namespaces.o
OBJS		+= uts_ns.o
OBJS		+= ipc_ns.o

DEPS		:= $(patsubst %.o,%.d,$(OBJS))

include Makefile.syscall
include Makefile.pie

all: $(PROGRAM)

%.o: %.c
	$(E) "  CC      " $@
	$(Q) $(CC) -c $(CFLAGS) $< -o $@

%.i: %.c
	$(E) "  CC      " $@
	$(Q) $(CC) -E $(CFLAGS) $< -o $@

%.s: %.c
	$(E) "  CC      " $@
	$(Q) $(CC) -S $(CFLAGS) -fverbose-asm $< -o $@

$(PROGRAM): $(OBJS) | $(SYS-OBJ) $(PIE-GEN)
	$(E) "  LINK    " $@
	$(Q) $(CC) $(CFLAGS) $(OBJS) $(LIBS) $(SYS-OBJ) -o $@

%.d: %.c | $(SYS-OBJ) $(PIE-GEN)
	$(Q) $(CC) -M -MT $(patsubst %.d,%.o,$@) $(CFLAGS) $< -o $@

test-legacy: $(PROGRAM)
	$(Q) $(MAKE) -C test/legacy all
.PHONY: test-legacy

zdtm: $(PROGRAM)
	$(Q) $(MAKE) -C test/zdtm all
.PHONY: zdtm

test: zdtm
	$(Q) $(SH) test/zdtm.sh
.PHONY: test

rebuild:
	$(E) "  FORCE-REBUILD"
	$(Q) $(RM) -f ./*.o
	$(Q) $(RM) -f ./*.d
	$(Q) $(MAKE)
.PHONY: rebuild

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
	$(Q) $(MAKE) -C test/legacy clean
	$(Q) $(MAKE) -C test/zdtm cleandep
	$(Q) $(MAKE) -C test/zdtm clean
	$(Q) $(MAKE) -C test/zdtm cleanout
	$(Q) $(MAKE) -C Documentation clean
.PHONY: clean

distclean: clean
	$(E) "  DISTCLEAN"
	$(Q) $(RM) -f ./tags
	$(Q) $(RM) -f ./cscope*
.PHONY: distclean

tags:
	$(E) "  GEN" $@
	$(Q) $(RM) -f tags
	$(Q) $(FIND) . -name '*.[hcS]' ! -path './.*' -print | xargs ctags -a
.PHONY: tags

cscope:
	$(E) "  GEN" $@
	$(Q) $(FIND) . -name '*.[hcS]' ! -path './.*' -print > cscope.files
	$(Q) $(CSCOPE) -bkqu
.PHONY: cscope

docs:
	$(Q) $(MAKE) -s -C Documentation all
.PHONY: docs

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
.PHONY: help

deps-targets := %.o %.s %.i $(PROGRAM) zdtm test-legacy

.DEFAULT_GOAL	:= $(PROGRAM)

ifneq ($(filter $(deps-targets), $(MAKECMDGOALS)),)
	INCDEPS := 1
endif

ifeq ($(MAKECMDGOALS),)
	INCDEPS := 1
endif

ifeq ($(INCDEPS),1)
-include $(DEPS)
endif
