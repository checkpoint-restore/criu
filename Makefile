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

ifeq ($(GMON),1)
        CFLAGS		+= -pg
        GMONLDOPT	+= -pg
export GMON GMONLDOPT
endif

CFLAGS			+= $(WARNINGS) $(DEFINES)

#
# Protobuf images first, they are not depending
# on anything else.
$(eval $(call gen-built-in,images))

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
.PHONY: lib

all: criu lib
.PHONY: all

subclean:
	$(call msg-clean, criu)
	$(Q) $(MAKE) -C lib clean
	$(Q) $(MAKE) -C Documentation clean
	$(Q) $(RM) .gitid
.PHONY: subclean

clean: subclean
	$(Q) $(MAKE) $(build)=images $@
	$(Q) $(MAKE) -C criu $@
.PHONY: clean

# mrproper depends on clean in nmk
mrproper: subclean
	$(Q) $(MAKE) $(build)=images $@
	$(Q) $(MAKE) -C criu $@
	$(Q) $(RM) cscope.*
	$(Q) $(RM) tags TAGS
.PHONY: mrproper

#
# Non-CRIU stuff.
#

docs:
	$(Q) $(MAKE) -s -C Documentation all
.PHONY: docs

zdtm: all
	$(Q) MAKEFLAGS= $(MAKE) -C test/zdtm all
.PHONY: zdtm

test: zdtm
	$(Q) MAKEFLAGS= $(MAKE) -C test
.PHONY: test

#
# Generating tar requires tag matched CRIU_VERSION.
# If not found then simply use GIT's describe with
# "v" prefix stripped.
head-name := $(shell git tag -l v$(CRIU_VERSION))
ifeq ($(head-name),)
        head-name := $(shell git describe)
endif
tar-name := $(shell echo $(head-name) | sed -e 's/^v//g')
criu-$(tar-name).tar.bz2:
	git archive --format tar --prefix 'criu-$(tar-name)/' $(head-name) | bzip2 > $@
dist tar: criu-$(tar-name).tar.bz2
	@true
.PHONY: dist tar

tags:
	$(call msg-gen, $@)
	$(Q) $(RM) tags
	$(Q) $(FIND) . -name '*.[hcS]' ! -path './.*' ! -path './test/*' -print | xargs $(CTAGS) -a
.PHONY: tags

etags:
	$(call msg-gen, $@)
	$(Q) $(RM) TAGS
	$(Q) $(FIND) . -name '*.[hcS]' ! -path './.*' ! -path './test/*' -print | xargs $(ETAGS) -a
.PHONY: etags


cscope:
	$(call msg-gen, $@)
	$(Q) $(FIND) . -name '*.[hcS]' ! -path './.*' ! -path './test/*' ! -type l -print > cscope.files
	$(Q) $(CSCOPE) -bkqu
.PHONY: cscope

gcov:
	$(E) " GCOV"
	$(Q) test -d gcov || mkdir gcov && \
	geninfo --output-filename gcov/criu.info --no-recursion criu/ && \
	cd gcov && \
	genhtml --rc lcov_branch_coverage=1 --output-directory html criu.info
	@echo "Code coverage report is in `pwd`/gcov/html/ directory."
.PHONY: gcov

docker-build:
	$(MAKE) -C scripts/build/ x86_64 
.PHONY: docker-build

docker-test:
	docker run --rm -it --privileged criu-x86_64 ./test/zdtm.py run -a -x tcp6 -x tcpbuf6 -x static/rtc -x cgroup
.PHONY: docker-test

help:
	@echo '    Targets:'
	@echo '      all             - Build all [*] targets'
	@echo '    * criu            - Build criu'
	@echo '      zdtm            - Build zdtm test-suite'
	@echo '      docs            - Build documentation'
	@echo '      install         - Install CRIU (see INSTALL.md)'
	@echo '      uninstall       - Uninstall CRIU'
	@echo '      dist            - Create a source tarball'
	@echo '      clean           - Clean most, but leave enough to navigate'
	@echo '      mrproper        - Delete all compiled/generated files'
	@echo '      tags            - Generate tags file (ctags)'
	@echo '      etags           - Generate TAGS file (etags)'
	@echo '      cscope          - Generate cscope database'
	@echo '      test            - Run zdtm test-suite'
	@echo '      gcov            - Make code coverage report'
.PHONY: help

include Makefile.install

.DEFAULT_GOAL := all

#
# Optional local include.
-include Makefile.local
