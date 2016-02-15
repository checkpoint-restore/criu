#
# CRIU version.
VERSION_MAJOR		:= 2
VERSION_MINOR		:= 0
VERSION_SUBLEVEL	:=
VERSION_EXTRA		:=
VERSION_NAME		:=

export VERSION_MAJOR VERSION_MINOR
export VERSION_SUBLEVEL VERSION_EXTRA VERSION_NAME

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

ifeq ($(ARCH),powerpc)
        ARCH		:= ppc64
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
$(SYSCALL-LIB): config
	$(Q) $(MAKE) $(call build-as,Makefile.syscalls,$(ARCH_DIR)) all
PHONY += $(SYSCALL-LIB)

#
# Architecture dependant part.
ARCH-LIB		:= $(ARCH_DIR)/crtools.built-in.o
$(ARCH-LIB): config $(SYSCALL-LIB)
	$(Q) $(MAKE) $(call build-as,Makefile,$(ARCH_DIR)) $@
PHONY += $(ARCH-LIB)

#
# piegen tool needed for PIE code.
ifeq ($(piegen-y),y)
piegen			:= pie/piegen/piegen

pie/piegen/%: config
	$(Q) CC=$(HOSTCC) LD=$(HOSTLD) CFLAGS="$(HOSTCFLAGS) $(WARNINGS) $(DEFINES)" $(MAKE) $(build)=pie/piegen $@
pie/piegen: config
	$(Q) CC=$(HOSTCC) LD=$(HOSTLD) CFLAGS="$(HOSTCFLAGS) $(WARNINGS) $(DEFINES)" $(MAKE) $(build)=pie/piegen all
$(piegen): pie/piegen/built-in.o
	$(call msg-link, $@)
	$(Q) $(HOSTCC) $(HOSTCFLAGS) $^ $(LDFLAGS) -o $@
PHONY += pie/piegen
endif

#
# PIE library code.
pie/lib.a: $(ARCH-LIB) $(SYSCALL-LIB)
	$(Q) $(MAKE) $(call build-as,Makefile.library,pie) all

#
# PIE code blobs themseves.
pie: $(ARCH_DIR) $(piegen) pie/lib.a
	$(Q) $(MAKE) $(build)=pie all
PHONY += pie

#
# CRIU executable
PROGRAM-BUILTINS	+= ../images/built-in.o
PROGRAM-BUILTINS	+= built-in.o
PROGRAM-BUILTINS	+= pie/lib.a
PROGRAM-BUILTINS	+= $(SYSCALL-LIB)

LIBS			+= arch/$(ARCH)/crtools.built-in.o

built-in.o: pie
	$(Q) $(MAKE) $(call build-as,Makefile.crtools,.) all

criu: $(PROGRAM-BUILTINS) built-in.o
	$(call msg-link, $@)
	$(Q) $(CC) $(CFLAGS) $^ $(LIBS) $(LDFLAGS) $(GMONLDOPT) -rdynamic -o $@
PHONY += criu

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

#
# Final @all target.
all: $(PHONY)
	@true

.PHONY: $(PHONY) clean
