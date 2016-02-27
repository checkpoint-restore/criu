#
# Import the build engine first
__nmk_dir=$(CURDIR)/scripts/nmk/scripts/
export __nmk_dir

include $(__nmk_dir)/include.mk
include $(__nmk_dir)/macro.mk

#
# Import tools versions early
# so subsequents may refer them.
include Makefile.versions

#
# To build host helpers.
HOSTCC		?= gcc
HOSTLD		?= ld
export HOSTCC HOSTLD

CFLAGS		+= $(USERCFLAGS)
export CFLAGS

HOSTCFLAGS	?= $(CFLAGS)
export HOSTCFLAGS

#
# Where we live.
SRC_DIR	:= $(CURDIR)
export SRC_DIR

#
# General architecture specific options.
UNAME-M := $(shell uname -m)
export UNAME-M

ifeq ($(ARCH),arm)
        ARMV		:= $(shell echo $(UNAME-M) | sed -nr 's/armv([[:digit:]]).*/\1/p; t; i7')
        DEFINES		:= -DCONFIG_ARMV$(ARMV)

        USERCFLAGS += -Wa,-mimplicit-it=always

        ifeq ($(ARMV),6)
                USERCFLAGS += -march=armv6
        endif

        ifeq ($(ARMV),7)
                USERCFLAGS += -march=armv7-a
        endif

        PROTOUFIX	:= y
endif

ifeq ($(ARCH),x86)
        DEFINES		:= -DCONFIG_X86_64
endif

ifeq ($(ARCH),aarch64)
	VDSO         := y
endif

#
# The PowerPC 64 bits architecture could be big or little endian.
# They are handled in the same way.
#
ifeq ($(ARCH),ppc64)
        ifeq ($(UNAME-M),ppc64)
                error := $(error ppc64 big endian not yet supported)
        endif

        DEFINES		:= -DCONFIG_PPC64
endif

export PROTOUFIX DEFINES USERCFLAGS

#
# Independent options for all tools.
DEFINES			+= -D_FILE_OFFSET_BITS=64
DEFINES			+= -D_GNU_SOURCE

CFLAGS			+= $(USERCFLAGS)

WARNINGS		:= -Wall

CFLAGS-GCOV		:= --coverage -fno-exceptions -fno-inline
export CFLAGS-GCOV

ifeq ($(GCOV),1)
        LDFLAGS         += -lgcov
        DEBUG           := 1
        CFLAGS          += $(CFLAGS-GCOV)
endif

ifneq ($(WERROR),0)
        WARNINGS	+= -Werror
endif

ifeq ($(DEBUG),1)
        DEFINES		+= -DCR_DEBUG
        CFLAGS		+= -O0 -ggdb3
else
        CFLAGS		+= -O2 -g
endif

CFLAGS			+= $(WARNINGS) $(DEFINES)

#
# Protobuf images first, they are not depending
# on anything else.
$(eval $(call gen-built-in,images))
PHONY += images

#
# CRIU building done in own directory
# with slightly different rules so we
# can't use nmk engine directly (we
# build syscalls library and such).
#
# But note that we're already included
# the nmk so we can reuse it there.
criu/%: images/built-in.o
	$(Q) $(MAKE) -C criu $@
criu: images/built-in.o
	$(Q) $(MAKE) -C criu all
.PHONY: criu

#
# Libraries next once criu it ready
# (we might generate headers and such
# when building criu itself).
lib/%: criu
	$(Q) $(MAKE) -C lib $@
lib: criu
	$(Q) $(MAKE) -C lib all
PHONY += lib

all: criu lib
PHONY += all

clean-built:
	$(Q) $(MAKE) $(build)=images clean
	$(Q) $(MAKE) -C criu clean
	$(Q) $(MAKE) -C lib clean
	$(Q) $(MAKE) -C Documentation clean
PHONY += clean-built

clean: clean-built
	$(call msg-clean, criu)
	$(Q) $(RM) cscope.*
	$(Q) $(RM) tags TAGS
PHONY += clean

#
# Non-CRIU stuff.
#

docs:
	$(Q) $(MAKE) -s -C Documentation all
PHONY += docs

zdtm: all
	$(Q) MAKEFLAGS= $(MAKE) -C test/zdtm all
PHONY += zdtm

test: zdtm
	$(Q) MAKEFLAGS= $(MAKE) -C test
PHONY += test

tar-name := $(shell git tag -l v$(CRIU_VERSION))
ifeq ($(tar-name),)
        tar-name := $(shell git describe)
endif
criu-$(tar-name).tar.bz2:
	git archive --format tar --prefix 'criu-$(tar-name)/' $(tar-name) | bzip2 > $@
dist tar: criu-$(tar-name).tar.bz2
	@true
.PHONY: dist tar

tags:
	$(call msg-gen, $@)
	$(Q) $(RM) tags
	$(Q) $(FIND) . -name '*.[hcS]' ! -path './.*' ! -path './test/*' -print | xargs $(CTAGS) -a
PHONY += tags

etags:
	$(call msg-gen, $@)
	$(Q) $(RM) TAGS
	$(Q) $(FIND) . -name '*.[hcS]' ! -path './.*' ! -path './test/*' -print | xargs $(ETAGS) -a
PHONY += etags


cscope:
	$(call msg-gen, $@)
	$(Q) $(FIND) . -name '*.[hcS]' ! -path './.*' ! -path './test/*' ! -type l -print > cscope.files
	$(Q) $(CSCOPE) -bkqu
PHONY += cscope

gcov:
	$(E) " GCOV"
	$(Q) test -d gcov || mkdir gcov && \
	cp criu/*.{gcno,c,h} test/`pwd`/criu/   && \
	geninfo --output-filename gcov/crtools.h.info --no-recursion criu/ && \
	geninfo --output-filename gcov/crtools.ns.info --no-recursion test/`pwd`/criu/ && \
	sed -i "s#/test`pwd`##" gcov/crtools.ns.info && \
	cd gcov && \
	lcov --rc lcov_branch_coverage=1 --add-tracefile crtools.h.info \
	--add-tracefile crtools.ns.info --output-file criu.info && \
	genhtml --rc lcov_branch_coverage=1 --output-directory html criu.info
	@echo "Code coverage report is in `pwd`/gcov/html/ directory."
PHONY += gcov

docker-build:
	$(MAKE) -C scripts/build/ x86_64 

PHONY += docker-build

docker-test:
	docker run --rm -it --privileged criu-x86_64 ./test/zdtm.py run -a -x tcp6 -x tcpbuf6 -x static/rtc -x cgroup
PHONY += docker-test

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
	@echo '      etags           - Generate TAGS file (etags)'
	@echo '      cscope          - Generate cscope database'
	@echo '      rebuild         - Force-rebuild of [*] targets'
	@echo '      test            - Run zdtm test-suite'
	@echo '      gcov            - Make code coverage report'
PHONY += help

include Makefile.install

.PHONY: $(PHONY)

.DEFAULT_GOAL := all

#
# Optional local include.
-include Makefile.local
