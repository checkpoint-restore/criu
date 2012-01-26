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

OBJS_GEN_DEP	+= parasite-syscall.o
OBJS_GEN_DEP	+= cr-restore.o
DEPS_GEN	:= $(patsubst %.o,%.d,$(OBJS_GEN_DEP))

OBJS		+= $(OBJS_GEN_DEP)
OBJS		+= crtools.o
OBJS		+= proc_parse.o
OBJS		+= cr-dump.o
OBJS		+= cr-show.o
OBJS		+= util.o
OBJS		+= ptrace.o
OBJS		+= log.o
OBJS		+= libnetlink.o
OBJS		+= sockets.o
OBJS		+= files.o
OBJS		+= namespaces.o

OBJS-BLOB	+= parasite.o
SRCS-BLOB	+= $(patsubst %.o,%.c,$(OBJS-BLOB))

HEAD-BLOB-GEN	:= $(patsubst %.o,%-blob.h,$(OBJS-BLOB))
HEAD-BIN	:= $(patsubst %.o,%.bin,$(OBJS-BLOB))
HEAD-LDS	:= $(patsubst %.o,%.lds.S,$(OBJS-BLOB))

ROBJS-BLOB	:= restorer.o
#
# Everything embedded into restorer as a separate
# object file should go here.
ROBJS		:= $(ROBJS-BLOB)
ROBJS		+= restorer-log.o

RDEPS-BLOB	+= $(patsubst %.o,%.d,$(ROBJS))
RSRCS-BLOB	+= $(patsubst %.o,%.c,$(ROBJS))

RSRCS-BLOB	+= $(patsubst %.o,%.c,$(ROBJS-BLOB))

RHEAD-BLOB-GEN	:= $(patsubst %.o,%-blob.h,$(ROBJS-BLOB))
RHEAD-BIN	:= $(patsubst %.o,%.bin,$(ROBJS-BLOB))
RHEAD-LDS	:= $(patsubst %.o,%.lds.S,$(ROBJS-BLOB))

DEPS		:= $(patsubst %.o,%.d,$(OBJS))		\
       		   $(patsubst %.o,%.d,$(OBJS-BLOB))	\
		   $(patsubst %.o,%.d,$(ROBJS-BLOB))

all: $(PROGRAM)

$(OBJS-BLOB): $(SRCS-BLOB)
	$(E) "  CC      " $@
	$(Q) $(CC) -c $(CFLAGS) -fpic $< -o $@

$(HEAD-BIN): $(OBJS-BLOB) $(HEAD-LDS)
	$(E) "  GEN     " $@
	$(Q) $(LD) -T $(patsubst %.bin,%.lds.S,$@) $< -o $@

$(HEAD-BLOB-GEN): $(HEAD-BIN)
	$(E) "  GEN     " $@
	$(Q) $(SH) gen-offsets.sh			\
		parasite_h__				\
		parasite_blob_offset__			\
		parasite_blob				\
		$(OBJS-BLOB)				\
		$(HEAD-BIN) > parasite-blob.h
	$(Q) sync

$(ROBJS): $(RSRCS-BLOB)
	$(E) "  CC      " $@
	$(Q) $(CC) -c $(CFLAGS) -fpic $(patsubst %.o,%.c,$@) -o $@

$(RHEAD-BIN): $(ROBJS) $(RHEAD-LDS)
	$(E) "  GEN     " $@
	$(Q) $(LD) -T $(patsubst %.bin,%.lds.S,$@) -o $@ $(ROBJS)

$(RHEAD-BLOB-GEN): $(RHEAD-BIN) $(RDEPS-BLOB)
	$(E) "  GEN     " $@
	$(Q) $(SH) gen-offsets.sh			\
		restorer_h__				\
		restorer_blob_offset__			\
		restorer_blob				\
		$(ROBJS-BLOB)				\
		$(RHEAD-BIN) > restorer-blob.h
	$(Q) sync

%.o: %.c
	$(E) "  CC      " $@
	$(Q) $(CC) -c $(CFLAGS) $< -o $@

$(PROGRAM): $(OBJS)
	$(E) "  LINK    " $@
	$(Q) $(CC) $(CFLAGS) $(OBJS) $(LIBS) -o $@

$(DEPS_GEN): $(HEAD-BLOB-GEN) $(RHEAD-BLOB-GEN)
%.d: %.c
	$(Q) $(CC) -M -MT $(patsubst %.d,%.o,$@) $(CFLAGS) $< -o $@

test-legacy:
	$(Q) $(MAKE) -C test/legacy all
.PHONY: test-legacy

zdtm:
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

clean:
	$(E) "  CLEAN"
	$(Q) $(RM) -f ./*.o
	$(Q) $(RM) -f ./*.d
	$(Q) $(RM) -f ./*.img
	$(Q) $(RM) -f ./*.out
	$(Q) $(RM) -f ./*.bin
	$(Q) $(RM) -f ./tags
	$(Q) $(RM) -f ./cscope*
	$(Q) $(RM) -f ./$(PROGRAM)
	$(Q) $(RM) -f ./$(HEAD-BLOB-GEN)
	$(Q) $(RM) -f ./$(RHEAD-BLOB-GEN)
	$(Q) $(MAKE) -C test/legacy clean
	$(Q) $(MAKE) -C test/zdtm cleandep
	$(Q) $(MAKE) -C test/zdtm clean
	$(Q) $(MAKE) -C test/zdtm cleanout
.PHONY: clean

tags:
	$(E) "  GEN" $@
	$(Q) $(RM) -f tags
	$(Q) $(FIND) . -name '*.[hcS]' -print | xargs ctags -a
.PHONY: tags

cscope:
	$(E) "  GEN" $@
	$(Q) $(FIND) . -name '*.[hcS]' -print > cscope.files
	$(Q) $(CSCOPE) -bkqu
.PHONY: cscope

ifeq ($(filter-out no-deps-targets, $(MAKECMDGOALS)),)
-include $(DEPS)
endif
