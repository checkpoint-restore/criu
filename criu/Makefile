# here is a workaround for a bug in libnl-3:
# 6a8d90f5fec4 "attr: Allow attribute type 0"
WRAPFLAGS		+= -Wl,--wrap=nla_parse,--wrap=nlmsg_parse

ARCH_DIR		:= criu/arch/$(ARCH)
PIE_DIR			:= criu/pie
export ARCH_DIR PIE_DIR

ifeq ($(filter clean mrproper,$(MAKECMDGOALS)),)
        CFLAGS		+= $(shell $(COMPEL_BIN) includes)
        COMPEL_LIBS	:= $(shell $(COMPEL_BIN) --static libs)
        CFLAGS_PIE	+= $(shell $(COMPEL_BIN) cflags)
endif

#
# Configuration file paths
CONFIG-DEFINES		+= -DSYSCONFDIR='"/etc"'
CONFIG-DEFINES		+= -DGLOBAL_CONFIG_DIR='"/etc/criu/"'
CONFIG-DEFINES		+= -DDEFAULT_CONFIG_FILENAME='"default.conf"'
CONFIG-DEFINES		+= -DUSER_CONFIG_DIR='".criu/"'

#
# General flags.
CFLAGS			+= -fno-strict-aliasing
CFLAGS			+= -iquote criu/include
CFLAGS			+= -iquote include
CFLAGS			+= -iquote images
CFLAGS			+= -iquote $(ARCH_DIR)/include
CFLAGS			+= -iquote .
CFLAGS			+= $(shell $(PKG_CONFIG) --cflags libnl-3.0)
CFLAGS			+= $(CONFIG-DEFINES)

ifeq ($(GMON),1)
	CFLAGS		+= -pg
	GMONLDOPT	:= -pg
endif

# msg-* printing
include $(__nmk_dir)msg.mk

#
# Needed libraries checks
include criu/Makefile.packages

#
# Architecture dependent part.
ARCH-LIB		:= $(ARCH_DIR)/crtools.built-in.o
$(ARCH-LIB): .FORCE
	$(Q) $(MAKE) $(build)=$(ARCH_DIR) all

#
# PIE library code.
criu/pie/pie.lib.a: $(ARCH-LIB) .FORCE
	$(Q) $(MAKE) $(call build-as,Makefile.library,criu/pie) all

#
# PIE code blobs themseves.
pie: criu/pie/pie.lib.a
	$(Q) $(MAKE) $(build)=criu/pie all
.PHONY: pie

criu/pie/Makefile: ;
criu/pie/Makefile.library: ;
criu/pie/%: pie ;

#
# CRIU executable
PROGRAM-BUILTINS	+= criu/pie/pie.lib.a
PROGRAM-BUILTINS	+= images/built-in.o
PROGRAM-BUILTINS	+= $(obj)/built-in.o
PROGRAM-BUILTINS	+= $(ARCH-LIB)
PROGRAM-BUILTINS	+= soccr/libsoccr.a
PROGRAM-BUILTINS	+= $(COMPEL_LIBS)

$(obj)/built-in.o: pie
	$(Q) $(MAKE) $(call build-as,Makefile.crtools,criu) all


$(obj)/Makefile: ;
$(obj)/Makefile.crtools: ;
$(obj)/Makefile.packages: ;

$(obj)/%: pie
	$(Q) $(MAKE) $(call build-as,Makefile.crtools,criu) $@

$(obj)/criu: $(PROGRAM-BUILTINS)
	$(call msg-link, $@)
	$(Q) $(CC) $(CFLAGS) $^ $(LDFLAGS) $(LIBS) $(WRAPFLAGS) $(GMONLDOPT) -rdynamic -o $@

UNIT-BUILTINS		+= $(obj)/util.o
UNIT-BUILTINS		+= $(obj)/config.o
UNIT-BUILTINS		+= $(obj)/log.o
UNIT-BUILTINS		+= $(obj)/string.o
UNIT-BUILTINS		+= $(obj)/unittest/built-in.o

$(obj)/unittest/Makefile: ;

$(obj)/unittest/%: .FORCE

$(obj)/unittest/built-in.o: .FORCE
	$(Q) $(MAKE) $(call build-as,Makefile,criu/unittest) all

$(obj)/unittest/unittest: $(UNIT-BUILTINS)
	$(call msg-link, $@)
	$(Q) $(CC) $(CFLAGS) $^ $(LDFLAGS) $(LIBS) $(WRAPFLAGS) -rdynamic -o $@

unittest: $(obj)/unittest/unittest
	$(Q) $(obj)/unittest/$@

.PHONY: unittest

#
# Clean the most, except generated c files
subclean:
	$(Q) $(RM) $(obj)/*.{gcda,gcno,gcov}
	$(Q) $(RM) $(obj)/pie/*.{gcda,gcno,gcov}
	$(Q) $(RM) -r $(obj)/gcov
	$(Q) $(MAKE) $(build)=$(ARCH_DIR) clean
	$(Q) $(MAKE) $(call build-as,Makefile.library,$(PIE_DIR)) clean
	$(Q) $(MAKE) $(call build-as,Makefile.crtools,criu) clean
	$(Q) $(MAKE) $(call build-as,Makefile,criu/unittest) clean
	$(Q) $(MAKE) $(build)=$(PIE_DIR) clean
.PHONY: subclean
cleanup-y      += $(obj)/criu
clean: subclean

#
# Delete all generated files
subproper:
	$(Q) $(MAKE) $(build)=$(ARCH_DIR) mrproper
	$(Q) $(MAKE) $(call build-as,Makefile.library,$(PIE_DIR)) mrproper
	$(Q) $(MAKE) $(call build-as,Makefile.crtools,criu) mrproper
	$(Q) $(MAKE) $(build)=$(PIE_DIR) mrproper
.PHONY: subproper
mrproper: subproper

UAPI_HEADERS := criu/include/criu-plugin.h
UAPI_HEADERS += criu/include/criu-log.h

install: $(obj)/criu
	$(E) "  INSTALL " $(obj)/criu
	$(Q) mkdir -p $(DESTDIR)$(SBINDIR)
	$(Q) install -m 755 $(obj)/criu $(DESTDIR)$(SBINDIR)
	$(Q) mkdir -p $(DESTDIR)$(INCLUDEDIR)/criu/
	$(Q) install -m 644 $(UAPI_HEADERS) $(DESTDIR)$(INCLUDEDIR)/criu/
	$(Q) mkdir -p $(DESTDIR)$(LIBEXECDIR)/criu/scripts
	$(Q) install -m 755 scripts/systemd-autofs-restart.sh $(DESTDIR)$(LIBEXECDIR)/criu/scripts
	$(E) "  INSTALL " scripts/criu-ns
	$(Q) install -m 755 scripts/criu-ns $(DESTDIR)$(SBINDIR)
.PHONY: install

uninstall:
	$(E) " UNINSTALL" criu
	$(Q) $(RM) $(addprefix $(DESTDIR)$(SBINDIR)/,criu)
	$(Q) $(RM) $(addprefix $(DESTDIR)$(SBINDIR)/,criu-ns)
	$(Q) $(RM) $(addprefix $(DESTDIR)$(INCLUDEDIR)/criu/,$(notdir $(UAPI_HEADERS)))
	$(Q) $(RM) $(addprefix $(DESTDIR)$(LIBEXECDIR)/criu/scripts/,systemd-autofs-restart.sh)
.PHONY: uninstall

all-y += check-packages $(obj)/criu
