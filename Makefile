VERSION_MAJOR		:= 1
VERSION_MINOR		:= 1-rc1
VERSION_SUBLEVEL	:=
VERSION_EXTRA		:=
VERSION_NAME		:=

export VERSION_MAJOR VERSION_MINOR VERSION_SUBLEVEL VERSION_EXTRA VERSION_NAME

#
# FIXME zdtm building procedure requires implicit rules
# so I can't use strict make file mode and drop completely
# all of implicit rules, so I tuned only .SUFFIXES:
#
# In future zdtm makefiles need to be fixed and the line below
# may be uncommented.
#
#MAKEFLAGS := -r -R

include Makefile.inc
include Makefile.config

#
# Common definitions
#

FIND		:= find
CSCOPE		:= cscope
RM		:= rm -f
LD		:= $(CROSS_COMPILE)ld
CC		:= $(CROSS_COMPILE)gcc
NM		:= $(CROSS_COMPILE)nm
SH		:= bash
MAKE		:= make
OBJCOPY		:= $(CROSS_COMPILE)objcopy

#
# Fetch ARCH from the uname if not yet set
#
ARCH ?= $(shell uname -m | sed		\
		-e s/i.86/i386/		\
		-e s/sun4u/sparc64/	\
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

ifeq ($(shell echo $(ARCH) | sed -e 's/arm.*/arm/'),arm)
	ARMV         := $(shell echo $(ARCH) | sed -r -e 's/armv([[:digit:]]).*/\1/')
	ARCH         := arm
	DEFINES      := -DCONFIG_ARM -DCONFIG_ARMV$(ARMV)
	LDARCH       := arm

	ifeq ($(ARMV),6)
		CFLAGS += -march=armv6
	endif

	ifeq ($(ARMV),7)
		CFLAGS += -march=armv7-a
	endif
endif

LDARCH		?= $(ARCH)

SRC_DIR		?= $(CURDIR)
ARCH_DIR	:= arch/$(ARCH)

$(if $(wildcard $(ARCH_DIR)),,$(error "The architecture $(ARCH) isn't supported"))

cflags-y		+= -iquote include -iquote pie -iquote .
cflags-y		+= -iquote $(ARCH_DIR) -iquote $(ARCH_DIR)/include
cflags-y		+= -fno-strict-aliasing
export cflags-y

LIBS		:= -lrt -lpthread -lprotobuf-c -ldl

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
CRIU-LIB	:= lib/libcriu.so

export CC MAKE CFLAGS LIBS ARCH DEFINES MAKEFLAGS
export SRC_DIR SYSCALL-LIB SH RM ARCH_DIR OBJCOPY LDARCH LD
export cflags-y

include scripts/Makefile.version
include scripts/Makefile.rules

.SUFFIXES:

#
# shorthand
build := -r -R -f scripts/Makefile.build makefile=Makefile obj
build-crtools := -r -R -f scripts/Makefile.build makefile=Makefile.crtools obj

PROGRAM		:= criu

.PHONY: all zdtm test rebuild clean distclean tags cscope	\
	docs help pie protobuf arch/$(ARCH) clean-built lib

ifeq ($(GCOV),1)
%.o $(PROGRAM): override CFLAGS += --coverage
endif

all: config pie $(VERSION_HEADER) $(CRIU-LIB)
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

%.o %.i %.s %.d: $(VERSION_HEADER) pie
	$(Q) $(MAKE) $(build-crtools)=. $@
built-in.o: $(VERSION_HEADER) pie
	$(Q) $(MAKE) $(build-crtools)=. $@

lib/%:: $(VERSION_HEADER) config built-in.o
	$(Q) $(MAKE) $(build)=lib $@
lib: $(VERSION_HEADER) config built-in.o
	$(Q) $(MAKE) $(build)=lib all

PROGRAM-BUILTINS	+= pie/util-fd.o
PROGRAM-BUILTINS	+= pie/util.o
PROGRAM-BUILTINS	+= protobuf/built-in.o
PROGRAM-BUILTINS	+= built-in.o

$(ARCH_DIR)/vdso-pie.o: pie
	$(Q) $(MAKE) $(build)=pie $(ARCH_DIR)/vdso-pie.o
PROGRAM-BUILTINS	+= $(ARCH_DIR)/vdso-pie.o

$(PROGRAM): $(SYSCALL-LIB) $(ARCH-LIB) $(PROGRAM-BUILTINS)
	$(E) "  LINK    " $@
	$(Q) $(CC) $(CFLAGS) $^ $(LIBS) $(LDFLAGS) -rdynamic -o $@

zdtm: all
	$(Q) $(MAKE) -C test/zdtm all

test: zdtm
	$(Q) $(SH) test/zdtm.sh -C

clean-built:
	$(Q) $(RM) $(VERSION_HEADER)
	$(Q) $(MAKE) $(build)=arch/$(ARCH) clean
	$(Q) $(MAKE) $(build)=protobuf clean
	$(Q) $(MAKE) $(build)=pie clean
	$(Q) $(MAKE) $(build)=lib clean
	$(Q) $(MAKE) $(build-crtools)=. clean
	$(Q) $(MAKE) -C Documentation clean
	$(Q) $(RM) ./include/config.h
	$(Q) $(RM) ./$(PROGRAM)

rebuild: clean-built
	$(E) "  FORCE-REBUILD"
	$(Q) $(MAKE)

clean: clean-built
	$(E) "  CLEAN"
	$(Q) $(RM) ./*.img
	$(Q) $(RM) ./*.out
	$(Q) $(RM) ./*.bin
	$(Q) $(RM) -r ./test/dump/
	$(Q) $(RM) ./*.gcov ./*.gcda ./*.gcno
	$(Q) $(RM) -r ./gcov
	$(Q) $(RM) -r ./test/lib/
	$(Q) $(RM) -r ./test/lib64/
	$(Q) $(RM) protobuf-desc-gen.h
	$(Q) $(MAKE) -C test/zdtm cleandep clean cleanout
	$(Q) $(MAKE) -C test/libcriu clean

distclean: clean
	$(E) "  DISTCLEAN"
	$(Q) $(RM) ./tags
	$(Q) $(RM) ./cscope*

tags:
	$(E) "  GEN     " $@
	$(Q) $(RM) tags
	$(Q) $(FIND) . -name '*.[hcS]' ! -path './.*' -print | xargs ctags -a

cscope:
	$(E) "  GEN     " $@
	$(Q) $(FIND) . -name '*.[hcS]' ! -path './.*' -print > cscope.files
	$(Q) $(CSCOPE) -bkqu

docs:
	$(Q) $(MAKE) -s -C Documentation all

dist: tar
tar: criu-$(CRTOOLSVERSION).tar.bz2
criu-$(CRTOOLSVERSION).tar.bz2:
	git archive --format tar --prefix 'criu-$(CRTOOLSVERSION)/' \
		v$(CRTOOLSVERSION) | bzip2 > $@
.PHONY: dist tar

install: $(PROGRAM) install-man
	$(E) "  INSTALL " $(PROGRAM)
	$(Q) mkdir -p $(DESTDIR)$(SBINDIR)
	$(Q) install -m 755 $(PROGRAM) $(DESTDIR)$(SBINDIR)
	$(Q) mkdir -p $(DESTDIR)$(SYSTEMDUNITDIR)
	$(Q) install -m 644 scripts/sd/criu.socket $(DESTDIR)$(SYSTEMDUNITDIR)
	$(Q) install -m 644 scripts/sd/criu.service $(DESTDIR)$(SYSTEMDUNITDIR)

install-man:
	$(Q) $(MAKE) -C Documentation install

.PHONY: install install-man

help:
	@echo '    Targets:'
	@echo '      all             - Build all [*] targets'
	@echo '    * criu            - Build criu'
	@echo '      zdtm            - Build zdtm test-suite'
	@echo '      docs            - Build documentation'
	@echo '      install         - Install binary and man page'
	@echo '      dist            - Create a source tarball'
	@echo '      clean           - Clean everything'
	@echo '      tags            - Generate tags file (ctags)'
	@echo '      cscope          - Generate cscope database'
	@echo '      rebuild         - Force-rebuild of [*] targets'
	@echo '      test            - Run zdtm test-suite'

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
.PHONY: gcov

.DEFAULT_GOAL	:= all
