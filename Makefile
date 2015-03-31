VERSION_MAJOR		:= 1
VERSION_MINOR		:= 5
VERSION_SUBLEVEL	:= 1
VERSION_EXTRA		:=
VERSION_NAME		:=
VERSION_SO_MAJOR	:= 1
VERSION_SO_MINOR	:= 0

export VERSION_MAJOR VERSION_MINOR VERSION_SUBLEVEL VERSION_EXTRA VERSION_NAME
export VERSION_SO_MAJOR VERSION_SO_MINOR

#
# FIXME zdtm building procedure requires implicit rules
# so I can't use strict make file mode and drop completely
# all of implicit rules, so I tuned only .SUFFIXES:
#
# In future zdtm makefiles need to be fixed and the line below
# may be uncommented.
#
#MAKEFLAGS := -r -R

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

CFLAGS		+= $(USERCFLAGS)

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
	SRCARCH      := x86-32
	DEFINES      := -DCONFIG_X86_32
	VDSO         := y
endif
ifeq ($(ARCH),x86_64)
	SRCARCH      := x86
	DEFINES      := -DCONFIG_X86_64
	LDARCH       := i386:x86-64
	VDSO         := y
endif

ifeq ($(shell echo $(ARCH) | sed -e 's/arm.*/arm/'),arm)
	ARMV         := $(shell echo $(ARCH) | sed -nr 's/armv([[:digit:]]).*/\1/p; t; i7')
	SRCARCH      := arm
	DEFINES      := -DCONFIG_ARMV$(ARMV)

	USERCFLAGS += -Wa,-mimplicit-it=always

	ifeq ($(ARMV),6)
		USERCFLAGS += -march=armv6
	endif

	ifeq ($(ARMV),7)
		USERCFLAGS += -march=armv7-a
	endif
endif
ifeq ($(ARCH),aarch64)
	VDSO         := y
endif

SRCARCH		?= $(ARCH)
LDARCH		?= $(SRCARCH)

SRC_DIR		?= $(CURDIR)
ARCH_DIR	:= arch/$(SRCARCH)

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

ifeq ($(GMON),1)
	CFLAGS	+= -pg
	GMONLDOPT = -pg
endif

CFLAGS		+= $(WARNINGS) $(DEFINES)
SYSCALL-LIB	:= $(ARCH_DIR)/syscalls.built-in.o
ARCH-LIB	:= $(ARCH_DIR)/crtools.built-in.o
CRIU-SO		:= libcriu
CRIU-LIB	:= lib/$(CRIU-SO).so
CRIU-INC	:= lib/criu.h include/criu-plugin.h include/criu-log.h protobuf/rpc.proto

export CC MAKE CFLAGS LIBS SRCARCH DEFINES MAKEFLAGS CRIU-SO
export SRC_DIR SYSCALL-LIB SH RM ARCH_DIR OBJCOPY LDARCH LD
export USERCFLAGS
export cflags-y
export VDSO

include Makefile.inc
include Makefile.config
include scripts/Makefile.version
include scripts/Makefile.rules

.SUFFIXES:

#
# shorthand
build := -r -R -f scripts/Makefile.build makefile=Makefile obj
build-crtools := -r -R -f scripts/Makefile.build makefile=Makefile.crtools obj

PROGRAM		:= criu

.PHONY: all zdtm test rebuild clean distclean tags cscope	\
	docs help pie protobuf $(ARCH_DIR) clean-built lib crit

ifeq ($(GCOV),1)
%.o $(PROGRAM): override CFLAGS += --coverage
endif

all: config pie $(VERSION_HEADER) $(CRIU-LIB)
	$(Q) $(MAKE) $(PROGRAM)
	$(Q) $(MAKE) crit

protobuf/%::
	$(Q) $(MAKE) $(build)=protobuf $@
protobuf:
	$(Q) $(MAKE) $(build)=protobuf all

$(ARCH_DIR)/%:: protobuf config
	$(Q) $(MAKE) $(build)=$(ARCH_DIR) $@
$(ARCH_DIR): protobuf config
	$(Q) $(MAKE) $(build)=$(ARCH_DIR) all

pie/%:: $(ARCH_DIR)
	$(Q) $(MAKE) $(build)=pie $@
pie: $(ARCH_DIR)
	$(Q) $(MAKE) $(build)=pie all

%.o %.i %.s %.d: $(VERSION_HEADER) pie
	$(Q) $(MAKE) $(build-crtools)=. $@
built-in.o: $(VERSION_HEADER) pie
	$(Q) $(MAKE) $(build-crtools)=. $@

lib/%:: $(VERSION_HEADER) config built-in.o
	$(Q) $(MAKE) $(build)=lib $@
lib: $(VERSION_HEADER) config built-in.o
	$(Q) $(MAKE) $(build)=lib all

ifeq ($(VDSO),y)
$(ARCH_DIR)/vdso-pie.o: pie
	$(Q) $(MAKE) $(build)=pie $(ARCH_DIR)/vdso-pie.o
PROGRAM-BUILTINS	+= $(ARCH_DIR)/vdso-pie.o
ifeq ($(SRCARCH),aarch64)
PROGRAM-BUILTINS	+= $(ARCH_DIR)/intraprocedure.o
endif
endif

PROGRAM-BUILTINS	+= pie/util-fd.o
PROGRAM-BUILTINS	+= pie/util.o
PROGRAM-BUILTINS	+= protobuf/built-in.o
PROGRAM-BUILTINS	+= built-in.o

$(SYSCALL-LIB) $(ARCH-LIB) $(PROGRAM-BUILTINS): config

$(PROGRAM): $(SYSCALL-LIB) $(ARCH-LIB) $(PROGRAM-BUILTINS)
	$(E) "  LINK    " $@
	$(Q) $(CC) $(CFLAGS) $^ $(LIBS) $(LDFLAGS) $(GMONLDOPT) -rdynamic -o $@

crit:
	$(Q) $(MAKE) -C pycriu all

zdtm: all
	$(Q) $(MAKE) -C test/zdtm all

test: zdtm
	$(Q) $(MAKE) -C test

clean-built:
	$(Q) $(RM) $(VERSION_HEADER)
	$(Q) $(MAKE) $(build)=$(ARCH_DIR) clean
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
	$(Q) $(RM) ./*.gcov ./*.gcda ./*.gcno
	$(Q) $(RM) -r ./gcov
	$(Q) $(RM) protobuf-desc-gen.h
	$(Q) $(MAKE) -C test $@
	$(Q) $(MAKE) -C pycriu $@
	$(Q) $(RM) ./*.pyc
	$(Q) $(RM) -r build

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

install: $(PROGRAM) $(CRIU-LIB) install-man install-crit
	$(E) "  INSTALL " $(PROGRAM)
	$(Q) mkdir -p $(DESTDIR)$(SBINDIR)
	$(Q) install -m 755 $(PROGRAM) $(DESTDIR)$(SBINDIR)
	$(Q) mkdir -p $(DESTDIR)$(LIBDIR)
	$(Q) install -m 755 $(CRIU-LIB) \
		$(DESTDIR)$(LIBDIR)/$(CRIU-SO).so.$(VERSION_SO_MAJOR).$(VERSION_SO_MINOR)
	$(Q) ln -fns $(CRIU-SO).so.$(VERSION_SO_MAJOR).$(VERSION_SO_MINOR) \
		$(DESTDIR)$(LIBDIR)/$(CRIU-SO).so.$(VERSION_SO_MAJOR)
	$(Q) ln -fns $(CRIU-SO).so.$(VERSION_SO_MAJOR).$(VERSION_SO_MINOR) \
		$(DESTDIR)$(LIBDIR)/$(CRIU-SO).so
	$(Q) mkdir -p $(DESTDIR)$(INCLUDEDIR)
	$(Q) install -m 644 $(CRIU-INC) $(DESTDIR)$(INCLUDEDIR)
	$(Q) mkdir -p $(DESTDIR)$(SYSTEMDUNITDIR)
	$(Q) install -m 644 scripts/sd/criu.socket $(DESTDIR)$(SYSTEMDUNITDIR)
	$(Q) install -m 644 scripts/sd/criu.service $(DESTDIR)$(SYSTEMDUNITDIR)
	$(Q) mkdir -p $(DESTDIR)$(LOGROTATEDIR)
	$(Q) install -m 644 scripts/logrotate.d/criu-service $(DESTDIR)$(LOGROTATEDIR)
	$(Q) sed -e 's,@version@,$(GITID),' \
		-e 's,@libdir@,$(LIBDIR),' \
		-e 's,@includedir@,$(dir $(INCLUDEDIR)),' \
		lib/criu.pc.in > criu.pc
	$(Q) mkdir -p $(DESTDIR)$(LIBDIR)/pkgconfig
	$(Q) install -m 644 criu.pc $(DESTDIR)$(LIBDIR)/pkgconfig

install-man:
	$(Q) $(MAKE) -C Documentation install

install-crit: crit
	$(E) "  INSTALL crit"
	$(Q) python scripts/crit-setup.py install --prefix=$(DESTDIR)

.PHONY: install install-man install-crit

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
