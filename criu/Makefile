# here is a workaround for a bug in libnl-3:
# 6a8d90f5fec4 "attr: Allow attribute type 0" 
WRAPFLAGS		+= -Wl,--wrap=nla_parse,--wrap=nlmsg_parse

ARCH_DIR		:= arch/$(SRCARCH)
export ARCH_DIR

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
# Needed libraries checks
include Makefile.packages

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
	$(Q) $(CC) $(CFLAGS) $^ $(ARCH-LIB) $(LIBS) $(WRAPFLAGS) $(LDFLAGS) $(GMONLDOPT) -rdynamic -o $@


subclean:
	$(Q) $(RM) ./*.{gcda,gcno,gcov}
	$(Q) $(RM) ./pie/*.{gcda,gcno,gcov}
	$(Q) $(RM) ./pie/piegen/*.{gcda,gcno,gcov}
	$(Q) $(RM) -r ./gcov
	$(Q) $(RM) criu
.PHONY: subclean

#
# Clean the most, except generated c files
clean: subclean
	$(Q) $(MAKE) $(call build-as,Makefile.syscalls,$(ARCH_DIR)) $@
	$(Q) $(MAKE) $(call build-as,Makefile,$(ARCH_DIR)) $@
	$(Q) $(MAKE) $(call build-as,Makefile.library,pie) $@
	$(Q) $(MAKE) $(call build-as,Makefile.crtools,.) $@
	$(Q) $(MAKE) $(build)=pie/piegen $@
	$(Q) $(MAKE) $(build)=pie $@
.PHONY: clean

#
# Delete all generated files
mrproper: subclean
	$(Q) $(MAKE) $(call build-as,Makefile.syscalls,$(ARCH_DIR)) $@
	$(Q) $(MAKE) $(call build-as,Makefile,$(ARCH_DIR)) $@
	$(Q) $(MAKE) $(call build-as,Makefile.library,pie) $@
	$(Q) $(MAKE) $(call build-as,Makefile.crtools,.) $@
	$(Q) $(MAKE) $(build)=pie/piegen $@
	$(Q) $(MAKE) $(build)=pie $@
	$(Q) $(RM) $(CONFIG_HEADER)
.PHONY: mrproper

UAPI_HEADERS := include/criu-plugin.h include/criu-log.h

install: criu
	$(E) "  INSTALL " criu
	$(Q) mkdir -p $(DESTDIR)$(SBINDIR)
	$(Q) install -m 755 criu $(DESTDIR)$(SBINDIR)
	$(Q) mkdir -p $(DESTDIR)$(INCLUDEDIR)
	$(Q) install -m 644 $(UAPI_HEADERS) $(DESTDIR)$(INCLUDEDIR)
	$(Q) mkdir -p $(DESTDIR)$(LIBEXECDIR)/criu/scripts
	$(Q) install -m 755 $(SRC_DIR)/scripts/systemd-autofs-restart.sh $(DESTDIR)$(LIBEXECDIR)/criu/scripts
.PHONY: install

uninstall:
	$(E) " UNINSTALL" criu
	$(Q) $(RM) $(addprefix $(DESTDIR)$(SBINDIR)/,criu)
	$(Q) $(RM) $(addprefix $(DESTDIR)$(INCLUDEDIR)/,$(notdir $(UAPI_HEADERS)))
	$(Q) $(RM) $(addprefix $(DESTDIR)$(LIBEXECDIR)/criu/scripts/,systemd-autofs-restart.sh)
.PHONY: uninstall

#
# Final @all target.
all: check-packages criu
	@true
.PHONY: all
