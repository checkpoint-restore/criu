#
# HOST part is needed to build helper
# tools such as piegen.
HOSTCC			?= gcc
HOSTLD			?= ld
HOSTCFLAGS		?= $(CFLAGS)
CFLAGS			+= $(USERCFLAGS)

export HOSTCC HOSTLD HOSTCFLAGS

ifeq ($(ARCH),x86)
        SRCARCH		:= x86
        LDARCH		:= i386:x86-64
        VDSO		:= y
endif

ifeq ($(ARCH),arm)
        SRCARCH		:= arm
endif

ifeq ($(ARCH),arm64)
        ARCH		:= aarch64
        SRCARCH		:= aarch64
        VDSO		:= y
endif

ifeq ($(ARCH),ppc64)
        SRCARCH		:= ppc64
        LDARCH		:= powerpc:common64
        VDSO		:= y
endif

LDARCH ?= $(SRCARCH)

export SRCARCH LDARCH VDSO

SRCARCH			?= $(ARCH)
LDARCH			?= $(SRCARCH)
ARCH_DIR		:= arch/$(SRCARCH)

export SRCARCH LDARCH ARCH_DIR VDSO

$(if $(wildcard $(ARCH_DIR)),,$(error "The architecture $(ARCH) isn't supported"))

#
# General flags.
ccflags-y		+= -fno-strict-aliasing
ccflags-y		+= -iquote $(SRC_DIR)/criu/include
ccflags-y		+= -iquote $(SRC_DIR)/images
ccflags-y		+= -iquote $(SRC_DIR)/criu/pie
ccflags-y		+= -iquote $(SRC_DIR)/criu/$(ARCH_DIR)
ccflags-y		+= -iquote $(SRC_DIR)/criu/$(ARCH_DIR)/include
ccflags-y		+= -iquote $(SRC_DIR)/
ccflags-y		+= -I/usr/include/libnl3

export ccflags-y

LIBS			:= -lrt -lpthread -lprotobuf-c -ldl -lnl-3
REQ-LIBS-NAMES          := libpthread libprotobuf-c libnl-3

#
# Make sure all required libs are installed
ifneq ($(MAKECMDGOALS),clean)
        ifneq ($(shell sh -c                                                            \
                        'TMP="$(OUTPUT)$(TMPOUT).$$$$";                                 \
                        echo "int main(int argc, char *argv[]) { return 0; }" |         \
                        "$(CC)" -x c - $(LIBS) -o "$$TMP" > /dev/null 2>&1 && echo y;   \
                        rm -f "$$TMP"'),y)
                $(error "Make sure '$(REQ-LIBS-NAMES)' libraries are installed")
        endif
endif
ifeq ($(GMON),1)
	CFLAGS		+= -pg
	GMONLDOPT	:= -pg
endif

#
# piegen tool might be disabled by hands. Don't use it until
# you know what you're doing.
ifneq ($(filter ia32 x86 ppc64,$(ARCH)),)
        ifneq ($(PIEGEN),no)
                piegen-y := y
                export piegen-y
        endif
endif

# msg-* printing
include $(__nmk_dir)/msg.mk

#
# Version header file.
include Makefile.version

#
# Configure variables.
include Makefile.config
config: $(VERSION_HEADER)

#
# System calls library.
SYSCALL-LIB		:= $(ARCH_DIR)/syscalls.built-in.o
syscalls_lib: config
	$(Q) $(MAKE) $(call build-as,Makefile.syscalls,$(ARCH_DIR)) all
.PHONY: syscalls_lib

#
# Architecture dependant part.
ARCH-LIB		:= $(ARCH_DIR)/crtools.built-in.o
arch_lib: syscalls_lib
	$(Q) $(MAKE) $(call build-as,Makefile,$(ARCH_DIR)) all
.PHONY: arch_lib

#
# piegen tool needed for PIE code.
ifeq ($(piegen-y),y)
piegen-bin		:= pie/piegen/piegen

pie/piegen/%: config
	$(Q) CC=$(HOSTCC) LD=$(HOSTLD) CFLAGS="$(ccflags-y) $(HOSTCFLAGS) $(WARNINGS) $(DEFINES)" $(MAKE) $(build)=pie/piegen $@
$(piegen-bin): pie/piegen/built-in.o
	$(call msg-link, $@)
	$(Q) $(HOSTCC) $(HOSTCFLAGS) $^ $(LDFLAGS) -o $@
endif

#
# PIE library code.
pie/lib.a: arch_lib
	$(Q) $(MAKE) $(call build-as,Makefile.library,pie) all

#
# PIE code blobs themseves.
pie: $(piegen-bin) pie/lib.a
	$(Q) $(MAKE) $(build)=pie all
.PHONY: pie

#
# CRIU executable
PROGRAM-BUILTINS	+= ../images/built-in.o
PROGRAM-BUILTINS	+= built-in.o
PROGRAM-BUILTINS	+= pie/lib.a

built-in.o: pie
	$(Q) $(MAKE) $(call build-as,Makefile.crtools,.) all

criu: $(PROGRAM-BUILTINS)
	$(call msg-link, $@)
	$(Q) $(CC) $(CFLAGS) $^ $(SYSCALL-LIB) $(ARCH-LIB) $(LIBS) $(LDFLAGS) $(GMONLDOPT) -rdynamic -o $@

#
# Cleanup everything.
clean:
	$(Q) $(MAKE) $(call build-as,Makefile.syscalls,$(ARCH_DIR)) $@
	$(Q) $(MAKE) $(call build-as,Makefile.library,pie) $@
	$(Q) $(MAKE) $(call build-as,Makefile.crtools,.) $@
	$(Q) $(MAKE) $(build)=pie/piegen $@
	$(Q) $(MAKE) $(build)=pie $@
	$(Q) $(RM) ./*.{gcda,gcno,gcov}
	$(Q) $(RM) ./pie/*.{gcda,gcno,gcov}
	$(Q) $(RM) ./pie/piegen/*.{gcda,gcno,gcov}
	$(Q) $(RM) -r ./gcov
	$(Q) $(RM) $(VERSION_HEADER)
	$(Q) $(RM) $(CONFIG_HEADER)
	$(Q) $(RM) criu
.PHONY: clean

UAPI_HEADERS := include/criu-plugin.h include/criu-log.h

install: criu
	$(E) "  INSTALL " criu
	$(Q) mkdir -p $(DESTDIR)$(SBINDIR)
	$(Q) install -m 755 criu $(DESTDIR)$(SBINDIR)
	$(Q) mkdir -p $(DESTDIR)$(INCLUDEDIR)
	$(Q) install -m 644 $(UAPI_HEADERS) $(DESTDIR)$(INCLUDEDIR)
.PHONY: install

#
# Final @all target.
all: criu
	@true
.PHONY: all
