# Static dependency builder for criu.
#
# Downloads and builds criu's library dependencies as static archives with
# pkg-config files under $(O)/install. The top-level `make static` target
# links criu against them.
#
#   make                   # build everything
#   make libnl             # build one dependency
#   make check-updates     # compare pinned versions with upstream releases
#   make clean             # remove all downloads and build output
#   make O=/some/dir       # output to /some/dir instead of ./out
#
# Versions and checksums live in versions.mk; update them with update.sh.
#
# Build-time code generators (protoc and protoc-gen-c) are not built here.
# They run only on the build machine and are taken from the host.

include versions.mk

# Each dependency's configure script reads CFLAGS / CPPFLAGS / LDFLAGS /
# LIBS from the environment. Toolchain flags inherited from a parent
# Makefile (e.g. criu's top-level CFLAGS, which contain clang-specific
# warning flags such as -Wno-unknown-warning-option) would otherwise leak
# into autoconf's "checking whether the C compiler works" tests and
# break gcc-based builds. unexport these to keep the dep build hermetic.
unexport CFLAGS CPPFLAGS LDFLAGS LIBS USERCFLAGS HOSTCFLAGS WARNINGS DEFINES
# CRIU exports its own installation paths. Dependencies must install only
# into INSTALL_DIR; in particular, LZ4 accepts both cases of these names.
unexport PREFIX EXEC_PREFIX BINDIR SBINDIR MANDIR RUNDIR LIBDIR INCLUDEDIR LIBEXECDIR PLUGINDIR DESTDIR PKGCONFIGDIR
unexport prefix exec_prefix bindir sbindir mandir rundir libdir includedir libexecdir plugindir pkgconfigdir

O                ?= $(CURDIR)/out
override O       := $(abspath $(O))
DOWNLOAD_DIR     := $(O)/downloads
SRC_DIR          := $(O)/src
INSTALL_DIR      := $(O)/install
STAMP_DIR        := $(O)/stamps

# Dependencies find each other only through the private prefix, never
# through libraries installed on the host.
export PKG_CONFIG_PATH :=
export PKG_CONFIG_LIBDIR := $(INSTALL_DIR)/lib/pkgconfig

J                ?= $(shell nproc 2>/dev/null || echo 4)
# Share one jobserver across dependencies and their recursive builds. When
# invoked directly without -j, J sets the overall parallelism limit.
ifeq ($(filter -j% --jobserver%,$(MAKEFLAGS)),)
MAKEFLAGS += -j$(J)
endif
# Fallback location holding a copy of every tarball under its download
# file name, tried when the upstream URL fails. Optional.
DEPS_MIRROR      ?=
CC               ?= cc
export CC

CURL             := curl -fsSL --retry 3
SHA256SUM        := sha256sum

.DEFAULT_GOAL    := all
.PHONY: all clean check check-cc check-updates print-url help FORCE

FORCE:

check:
	./test.sh
	./test-tools.sh

clean:
	rm -rf $(O)

help:
	@echo 'Static dependency builder for criu.'
	@echo
	@echo 'Targets:'
	@echo '  all            build all dependencies (default)'
	@echo '  <dep>          build a single dependency: $(DEPS)'
	@echo '  check-updates  compare pinned versions with upstream releases'
	@echo '  clean          remove all downloads and build output'
	@echo
	@echo 'Variables:'
	@echo '  O=<dir>        output directory (default: $$(CURDIR)/out)'
	@echo '  J=<n>          total parallel jobs without -j (default: nproc)'
	@echo '  CC=<cc>        C compiler (default: cc)'
	@echo '  DEPS_MIRROR=<url>  fallback base URL for tarballs (default: none)'

# Archives built by one compiler must not be mixed with those of another
# (e.g. glibc and musl). Record the compiler that populated O and refuse
# to reuse O with a different compiler command, target, or version.
CC_ID := $(shell { printf '%s\n' '$(CC)'; $(CC) -dumpmachine && $(CC) --version; } 2>/dev/null | \
                 $(SHA256SUM) | cut -c1-16)

check-cc:
	@mkdir -p $(O)
	@if [ -f $(O)/cc.id ] && [ "$$(cat $(O)/cc.id)" != "$(CC_ID)" ]; then \
	    echo "error: $(O) was built with a different compiler than '$(CC)'." >&2; \
	    echo "       Remove it or select another output directory." >&2; \
	    exit 1; \
	fi
	@echo "$(CC_ID)" > $(O)/cc.id

$(DOWNLOAD_DIR) $(SRC_DIR) $(INSTALL_DIR) $(STAMP_DIR): | check-cc
	@mkdir -p $@

# ---- Rule templates --------------------------------------------------------
# Dependencies are registered with a lower-case name, used for targets and
# directories, and the upper-case prefix of their variables in versions.mk.
#
# The download rule fetches the tarball, from $(DEPS_MIRROR) if the upstream
# URL fails and a mirror is set, and verifies its hash either way. The
# extract rule unpacks it into $(SRC_DIR)/<name>. --no-same-owner keeps tar,
# running as root in the build container, from restoring the uids recorded
# in a tarball, which a rootless container cannot map.

# $(call fetch-rules,name,VAR)
define fetch-rules
DEPS += $(1)
DEP_VARS += $(2)
$(1)_TARBALL := $(DOWNLOAD_DIR)/$(notdir $($(2)_URL))

# Changing the selected source must invalidate the stamps even when its
# tarball is already cached and older than the previous build.
$(STAMP_DIR)/$(1).source: FORCE | $(STAMP_DIR)
	@printf '%s\n' '$($(2)_VERSION)' '$($(2)_URL)' '$($(2)_SHA256)' > "$$@.tmp"
	@if cmp -s "$$@.tmp" "$$@"; then \
	    rm -f "$$@.tmp"; \
	else \
	    mv "$$@.tmp" "$$@"; \
	fi

$$($(1)_TARBALL): | $(DOWNLOAD_DIR)
	@echo "  DL      $$(@F)"
	@$(CURL) "$($(2)_URL)" -o "$$@.tmp" || \
	    { test -n "$(DEPS_MIRROR)" && \
	      echo "  DL      $$(@F) (mirror)" && \
	      $(CURL) "$(DEPS_MIRROR)/$$(@F)" -o "$$@.tmp"; }
	@echo "$($(2)_SHA256)  $$@.tmp" | $(SHA256SUM) -c - >/dev/null
	@mv "$$@.tmp" "$$@"

$(STAMP_DIR)/$(1).extracted: $$($(1)_TARBALL) $(STAMP_DIR)/$(1).source | $(SRC_DIR) $(STAMP_DIR)
	@echo "  EXTRACT $$(<F)"
	@echo "$($(2)_SHA256)  $$<" | $(SHA256SUM) -c - >/dev/null
	@rm -rf "$(SRC_DIR)/$(1)" && mkdir -p "$(SRC_DIR)/$(1)"
	@tar -xf "$$<" -C "$(SRC_DIR)/$(1)" --strip-components=1 --no-same-owner
	@touch "$$@"

$(1): $(STAMP_DIR)/$(1).built
endef

# Prerequisites of the build rule for NAME: its sources and the libraries
# listed in VAR_DEPS.
build-prereqs = $(STAMP_DIR)/$(1).extracted $(foreach d,$($(2)_DEPS),$(STAMP_DIR)/$(d).built)

# $(call autotools-rules,name,VAR): build a static-only autotools package
# with the extra arguments in VAR_CONFIGURE_ARGS, then run VAR_POST_INSTALL.
define autotools-rules
$(STAMP_DIR)/$(1).built: $(call build-prereqs,$(1),$(2)) | $(INSTALL_DIR)
	@echo "  BUILD   $(1)"
	cd $(SRC_DIR)/$(1) && \
	    CC='$(CC)' ./configure --prefix=$(INSTALL_DIR) \
	        --enable-static --disable-shared $($(2)_CONFIGURE_ARGS) && \
	    $$(MAKE) && \
	    $$(MAKE) install
	$($(2)_POST_INSTALL)
	@touch $$@
endef

# Register an autotools dependency, or only the fetch rules of a dependency
# with a hand-written build rule.
add-autotools-dep = $(eval $(call fetch-rules,$(1),$(2)))$(eval $(call autotools-rules,$(1),$(2)))
add-dep = $(eval $(call fetch-rules,$(1),$(2)))

# ---- Autotools dependencies ------------------------------------------------
# libnl: CRIU links only libnl-3; skip the command line tools.
LIBNL_CONFIGURE_ARGS := --disable-cli
$(call add-autotools-dep,libnl,LIBNL)

$(call add-autotools-dep,libnet,LIBNET)

# protobuf-c: only the runtime library. protoc-gen-c, which needs the C++
# protobuf library, comes from the host. Generated code checks at compile
# time that it is compatible with the runtime headers.
PROTOBUF_C_CONFIGURE_ARGS := --disable-protoc
# CRIU includes <google/protobuf-c/protobuf-c.h>, the layout of Fedora's
# protobuf-c-devel; upstream installs <protobuf-c/protobuf-c.h>.
PROTOBUF_C_POST_INSTALL := mkdir -p $(INSTALL_DIR)/include/google && \
	ln -sfn ../protobuf-c $(INSTALL_DIR)/include/google/protobuf-c
$(call add-autotools-dep,protobuf-c,PROTOBUF_C)

$(call add-autotools-dep,libmnl,LIBMNL)

LIBNFTNL_DEPS := libmnl
$(call add-autotools-dep,libnftnl,LIBNFTNL)

# libnftables: --with-mini-gmp avoids a libgmp dependency, --without-cli
# disables interactive editing support. libnftables.pc does not declare
# that the library needs libnftnl and libmnl, so a static link through
# pkg-config would miss them.
LIBNFTABLES_DEPS := libmnl libnftnl
LIBNFTABLES_CONFIGURE_ARGS := --with-mini-gmp --without-cli --disable-man-doc
LIBNFTABLES_POST_INSTALL := echo 'Requires.private: libnftnl libmnl' >> \
	$(INSTALL_DIR)/lib/pkgconfig/libnftables.pc
$(call add-autotools-dep,libnftables,LIBNFTABLES)

# util-linux: only libuuid.
UTIL_LINUX_CONFIGURE_ARGS := --disable-all-programs --enable-libuuid
$(call add-autotools-dep,util-linux,UTIL_LINUX)

# pcre2: required by libselinux.
$(call add-autotools-dep,pcre2,PCRE2)

# ---- Other dependencies ----------------------------------------------------
# libcap has no configure script. CRIU uses only its <sys/capability.h>
# header, which is installed together with the library. `lib=lib` installs
# under <prefix>/lib rather than /lib64 on x86_64 distros.
$(call add-dep,libcap,LIBCAP)
LIBCAP_MAKE_VARS := lib=lib prefix=$(INSTALL_DIR) CC='$(CC)' SHARED=no

$(STAMP_DIR)/libcap.built: $(call build-prereqs,libcap,LIBCAP) | $(INSTALL_DIR)
	@echo "  BUILD   libcap"
	$(MAKE) -C $(SRC_DIR)/libcap/libcap $(LIBCAP_MAKE_VARS)
	$(MAKE) -C $(SRC_DIR)/libcap/libcap install $(LIBCAP_MAKE_VARS)
	@touch $@

# lz4: only the static library; the lz4 command line tool is not needed.
$(call add-dep,lz4,LZ4)
LZ4_MAKE_VARS := PREFIX=$(INSTALL_DIR) libdir=$(INSTALL_DIR)/lib \
                 includedir=$(INSTALL_DIR)/include \
                 pkgconfigdir=$(INSTALL_DIR)/lib/pkgconfig BUILD_SHARED=no CC='$(CC)'

$(STAMP_DIR)/lz4.built: $(call build-prereqs,lz4,LZ4) | $(INSTALL_DIR)
	@echo "  BUILD   lz4"
	$(MAKE) -C $(SRC_DIR)/lz4/lib $(LZ4_MAKE_VARS)
	$(MAKE) -C $(SRC_DIR)/lz4/lib install $(LZ4_MAKE_VARS)
	@touch $@

# libsepol and libselinux use plain Makefiles. Their default CFLAGS contain
# -Werror, which breaks with newer compilers, so set CFLAGS explicitly.
# PYTHON and RUBY are only used for language bindings, which are not built.
SELINUX_MAKE_VARS := PREFIX=$(INSTALL_DIR) LIBDIR=$(INSTALL_DIR)/lib \
                     SHLIBDIR=$(INSTALL_DIR)/lib DISABLE_SHARED=y \
                     CC='$(CC)' CFLAGS='-O2 -I$(INSTALL_DIR)/include' \
                     PYTHON=true RUBY=true

# libsepol: libselinux needs its headers to build and lists it in
# libselinux.pc, but CRIU does not call into it. CIL is not needed.
$(call add-dep,libsepol,LIBSEPOL)

$(STAMP_DIR)/libsepol.built: $(call build-prereqs,libsepol,LIBSEPOL) | $(INSTALL_DIR)
	@echo "  BUILD   libsepol"
	$(MAKE) -C $(SRC_DIR)/libsepol/include install $(SELINUX_MAKE_VARS)
	$(MAKE) -C $(SRC_DIR)/libsepol/src install $(SELINUX_MAKE_VARS) DISABLE_CIL=y
	@touch $@

# libselinux: the top-level Makefile locates pcre2 through pkg-config.
LIBSELINUX_DEPS := pcre2 libsepol
$(call add-dep,libselinux,LIBSELINUX)

$(STAMP_DIR)/libselinux.built: $(call build-prereqs,libselinux,LIBSELINUX) | $(INSTALL_DIR)
	@echo "  BUILD   libselinux"
	$(MAKE) -C $(SRC_DIR)/libselinux install SUBDIRS='include src' $(SELINUX_MAKE_VARS)
	@touch $@

# ---- Top-level targets -----------------------------------------------------
.PHONY: $(DEPS)

all: $(DEPS)

# Print the latest upstream release of every dependency next to the pinned
# version. Release tags are mapped to versions with VAR_TAG_SED.
check-updates:
	@$(foreach v,$(DEP_VARS), \
	    latest=$$(git ls-remote --tags --refs $($(v)_GIT) | \
	        sed -E -n -e 's|.*refs/tags/||' -e '$($(v)_TAG_SED)' | sort -V | tail -n 1); \
	    if [ -z "$$latest" ]; then \
	        status='unknown'; \
	    elif [ "$$latest" = "$($(v)_VERSION)" ]; then \
	        status='up to date'; \
	    else \
	        status="update available: $$latest"; \
	    fi; \
	    printf '%-12s %-8s %s\n' $(v) $($(v)_VERSION) "$$status";)

# Used by update.sh: print the tarball URL of DEP for its current version.
print-url:
	@echo '$($(DEP)_URL)'
