# here is a workaround for a bug in libnl-3:
# 6a8d90f5fec4 "attr: Allow attribute type 0" 
WRAPFLAGS		+= -Wl,--wrap=nla_parse,--wrap=nlmsg_parse

ARCH_DIR		:= criu/arch/$(SRCARCH)
PIE_DIR			:= criu/pie
export ARCH_DIR PIE_DIR

#
# General flags.
ccflags-y		+= -fno-strict-aliasing
ccflags-y		+= -iquote $(SRC_DIR)/criu/include
ccflags-y		+= -iquote $(SRC_DIR)/images
ccflags-y		+= -iquote $(SRC_DIR)/criu/pie
ccflags-y		+= -iquote $(SRC_DIR)/$(ARCH_DIR)
ccflags-y		+= -iquote $(SRC_DIR)/$(ARCH_DIR)/include
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
include $(__nmk_dir)msg.mk

#
# Needed libraries checks
include $(SRC_DIR)/criu/Makefile.packages

#
# Configure variables.
CONFIG_HEADER := $(obj)/include/config.h
ifneq ($(filter-out clean mrproper,$(MAKECMDGOALS)),)
include $(SRC_DIR)/criu/Makefile.config
endif
config: $(VERSION_HEADER)

#
# System calls library.
SYSCALL-LIB		:= $(ARCH_DIR)/syscalls.built-in.o
syscalls_lib: config
	$(Q) $(MAKE) $(call build-as,Makefile.syscalls,$(ARCH_DIR)) all
.PHONY: syscalls_lib

#
# Architecture dependent part.
ARCH-LIB		:= $(ARCH_DIR)/crtools.built-in.o
$(ARCH-LIB): syscalls_lib
	$(Q) $(MAKE) $(build)=$(ARCH_DIR) all

#
# piegen tool needed for PIE code.
ifeq ($(piegen-y),y)
piegen-bin		:= criu/pie/piegen/piegen

criu/pie/piegen/%: config
	$(Q) CC=$(HOSTCC) LD=$(HOSTLD) CFLAGS="$(ccflags-y) $(HOSTCFLAGS) $(WARNINGS) $(DEFINES)" $(MAKE) $(build)=criu/pie/piegen $@
$(piegen-bin): criu/pie/piegen/built-in.o
	$(call msg-link, $@)
	$(Q) $(HOSTCC) $(HOSTCFLAGS) $^ $(LDFLAGS) -o $@
endif

#
# PIE library code.
criu/pie/lib.a: $(ARCH-LIB)
	$(Q) $(MAKE) $(call build-as,Makefile.library,criu/pie) all

#
# PIE code blobs themseves.
pie: $(piegen-bin) criu/pie/lib.a
	$(Q) $(MAKE) $(build)=criu/pie all
.PHONY: pie

#
# CRIU executable
PROGRAM-BUILTINS	+= criu/pie/lib.a
PROGRAM-BUILTINS	+= images/built-in.o
PROGRAM-BUILTINS	+= $(obj)/built-in.o
PROGRAM-BUILTINS	+= $(ARCH-LIB)

$(obj)/built-in.o: pie
	$(Q) $(MAKE) $(call build-as,Makefile.crtools,criu) all

$(obj)/criu: $(PROGRAM-BUILTINS)
	$(call msg-link, $@)
	$(Q) $(CC) $(CFLAGS) $^ $(LIBS) $(WRAPFLAGS) $(LDFLAGS) $(GMONLDOPT) -rdynamic -o $@


#
# Clean the most, except generated c files
subclean:
	$(Q) $(RM) $(obj)/*.{gcda,gcno,gcov}
	$(Q) $(RM) $(obj)/pie/*.{gcda,gcno,gcov}
	$(Q) $(RM) $(obj)/pie/piegen/*.{gcda,gcno,gcov}
	$(Q) $(RM) -r $(obj)/gcov
	$(Q) $(MAKE) $(call build-as,Makefile.syscalls,$(ARCH_DIR)) clean
	$(Q) $(MAKE) $(build)=$(ARCH_DIR) clean
	$(Q) $(MAKE) $(call build-as,Makefile.library,$(PIE_DIR)) clean
	$(Q) $(MAKE) $(call build-as,Makefile.crtools,criu) clean
	$(Q) $(MAKE) $(build)=$(PIE_DIR) clean
	$(Q) $(MAKE) $(build)=$(PIE_DIR)/piegen clean
.PHONY: subclean
cleanup-y      += $(obj)/criu
clean: subclean

#
# Delete all generated files
subproper:
	$(Q) $(MAKE) $(call build-as,Makefile.syscalls,$(ARCH_DIR)) mrproper
	$(Q) $(MAKE) $(build)=$(ARCH_DIR) mrproper
	$(Q) $(MAKE) $(call build-as,Makefile.library,$(PIE_DIR)) mrproper
	$(Q) $(MAKE) $(call build-as,Makefile.crtools,criu) mrproper
	$(Q) $(MAKE) $(build)=$(PIE_DIR) mrproper
	$(Q) $(MAKE) $(build)=$(PIE_DIR)/piegen mrproper
.PHONY: subproper
mrproper-y     += $(CONFIG_HEADER)
mrproper: subproper

UAPI_HEADERS := $(SRC_DIR)/criu/include/criu-plugin.h
UAPI_HEADERS += $(SRC_DIR)/criu/include/criu-log.h

install: $(obj)/criu
	$(E) "  INSTALL " $(obj)/criu
	$(Q) mkdir -p $(DESTDIR)$(SBINDIR)
	$(Q) install -m 755 $(obj)/criu $(DESTDIR)$(SBINDIR)
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

all-y += check-packages $(obj)/criu
