ifeq ($(strip $(V)),)
	E = @echo
	Q = @
else
	E = @\#
	Q =
endif
export E Q

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

CFLAGS		+= -I./include
CFLAGS		+= -O0 -ggdb3

LIBS		+= -lrt

# Additional ARCH settings for x86
ARCH ?= $(shell echo $(uname_M) | sed -e s/i.86/i386/ -e s/sun4u/sparc64/ \
                  -e s/arm.*/arm/ -e s/sa110/arm/ \
                  -e s/s390x/s390/ -e s/parisc64/parisc/ \
                  -e s/ppc.*/powerpc/ -e s/mips.*/mips/ \
                  -e s/sh[234].*/sh/ )

uname_M      := $(shell uname -m | sed -e s/i.86/i386/)
ifeq ($(uname_M),i386)
	ARCH         := x86
	DEFINES      += -DCONFIG_X86_32
endif
ifeq ($(uname_M),x86_64)
	ARCH         := x86
	DEFINES      += -DCONFIG_X86_64
endif

DEFINES		+= -D_FILE_OFFSET_BITS=64
DEFINES		+= -D_GNU_SOURCE

ifneq ($(WERROR),0)
	WARNINGS += -Werror
endif

WARNINGS	+= -Wall -Wno-unused
CFLAGS		+= $(WARNINGS) $(DEFINES)

PROGRAM		:= crtools
TESTEE		:= testee
TESTEE-TH	:= testee-threads
TESTEE-STATIC	:= testee-static

all: $(PROGRAM) $(TESTEE) $(TESTEE-TH) $(TESTEE-STATIC)

OBJS		+= crtools.o
OBJS		+= parasite-syscall.o
OBJS		+= cr-dump.o
OBJS		+= cr-restore.o
OBJS		+= cr-show.o
OBJS		+= util.o
OBJS		+= rbtree.o
OBJS		+= elf.o

OBJS-TESTEE	+= testee.o

OBJS-TESTEE-TH	+= testee-threads.o

OBJS-BLOB	+= parasite.o

DEPS		:= $(patsubst %.o,%.d,$(OBJS))
DEPS-TESTEE	:= $(patsubst %.o,%.d,$(OBJS-TESTEE))
DEPS-TESTEE-TH	:= $(patsubst %.o,%.d,$(OBJS-TESTEE-TH))
DEPS-BLOB	:= $(patsubst %.o,%.d,$(OBJS-BLOB))

SRCS-BLOB	+= $(patsubst %.o,%.c,$(OBJS-BLOB))

HEAD-BLOB	:= $(patsubst %.o,%.h,$(OBJS-BLOB))
HEAD-BLOB-GEN	:= $(patsubst %.o,%-blob.h,$(OBJS-BLOB))
HEAD-BIN	:= $(patsubst %.o,%.bin,$(OBJS-BLOB))
HEAD-LDS	:= $(patsubst %.o,%.lds.S,$(OBJS-BLOB))

HEAD-IDS	:= $(patsubst %.h,%_h__,$(subst -,_,$(HEAD-BLOB)))

$(OBJS-BLOB): $(SRCS-BLOB) $(DEPS-BLOB)
	$(E) "  CC      " $@
	$(Q) $(CC) -c $(CFLAGS) -fpic $< -o $@

$(HEAD-BIN): $(OBJS-BLOB) $(HEAD-LDS)
%.bin: %.o
	$(E) "  GEN     " $@
	$(Q) $(LD) -T $(patsubst %.bin,%.lds.S,$@) $< -o $@
	$(Q) $(LD) -T $(patsubst %.bin,%-elf.lds.S,$@) $< -o $@.o

$(HEAD-BLOB): $(DEPS-BLOB) $(HEAD-BIN)
%-blob.h: %.bin
%.h: %.bin
	$(E) "  GEN     " $@
	$(Q) $(SH) gen-offsets.sh					\
		$(subst -,_,$(patsubst %.h,%,$@))_h__			\
		$(subst -,_,$(patsubst %.h,%,$@))_blob_offset__		\
		$(subst -,_,$(patsubst %.h,%,$@))_blob			\
		$(patsubst %.h,%.o,$@)					\
		$(patsubst %.h,%.bin,$@) > $(patsubst %.h,%-blob.h,$@)

$(OBJS): $(HEAD-BLOB) $(DEPS)
$(OBJS-TESTEE): $(DEPS-TESTEE)
$(OBJS-TESTEE-TH): $(DEPS-TESTEE-TH)
%.o: %.c
	$(E) "  CC      " $@
	$(Q) $(CC) -c $(CFLAGS) $< -o $@

$(PROGRAM): $(OBJS)
	$(E) "  LINK    " $@
	$(Q) $(CC) $(OBJS) $(LIBS) -o $@

$(TESTEE): $(OBJS-TESTEE)
	$(E) "  LINK    " $@
	$(Q) $(CC) $(OBJS-TESTEE) -o $@

$(TESTEE-TH): $(OBJS-TESTEE-TH)
	$(E) "  LINK    " $@
	$(Q) $(CC) $(OBJS-TESTEE-TH) -lpthread -o $@

$(TESTEE-STATIC).o: testee-static.c
	$(Q) gcc -c -static -I./.include -o testee-static.o testee-static.c

$(TESTEE-STATIC): $(TESTEE-STATIC).o
	$(Q) gcc -o testee-static -static testee-static.o

$(DEPS):
$(DEPS-TESTEE):
$(DEPS-TESTEE-TH):
$(DEPS-BLOB):
%.d: %.c
	$(Q) $(CC) -M -MT $(patsubst %.d,%.o,$@) $(CFLAGS) $< -o $@

clean:
	$(E) "  CLEAN"
	$(Q) rm -f ./*.o
	$(Q) rm -f ./*.d
	$(Q) rm -f ./*.img
	$(Q) rm -f ./*.elf
	$(Q) rm -f ./*.out
	$(Q) rm -f ./*.bin
	$(Q) rm -f ./tags
	$(Q) rm -f ./cscope*
	$(Q) rm -f ./$(PROGRAM)
	$(Q) rm -f ./$(TESTEE)
	$(Q) rm -f ./$(TESTEE-STATIC)
	$(Q) rm -f ./$(TESTEE-TH)
	$(Q) rm -f ./$(HEAD-BLOB)
	$(Q) rm -f ./$(HEAD-BLOB-GEN)
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
