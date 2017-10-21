# here is a workaround for a bug in libnl-3:
# 6a8d90f5fec4 "attr: Allow attribute type 0" 
WRAPFLAGS		+= -Wl,--wrap=nla_parse,--wrap=nlmsg_parse

ARCH_DIR		:= criu/arch/$(SRCARCH)
PIE_DIR			:= criu/pie
export ARCH_DIR PIE_DIR

ifeq ($(filter clean mrproper,$(MAKECMDGOALS)),)
	COMPEL_UAPI_INCLUDES	:= $(shell $(COMPEL_BIN) includes)
	export COMPEL_UAPI_INCLUDES
	COMPEL_LIBS		:= $(shell $(COMPEL_BIN) --static libs)
endif

#
# General flags.
ccflags-y		+= -fno-strict-aliasing
ccflags-y		+= -iquote criu/include
ccflags-y		+= -iquote include
ccflags-y		+= -iquote images
ccflags-y		+= -iquote $(ARCH_DIR)/include
ccflags-y		+= -iquote .
ccflags-y		+= -I/usr/include/libnl3
ccflags-y		+= $(COMPEL_UAPI_INCLUDES)

export ccflags-y

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
	$(Q) $(CC) $(CFLAGS) $^ $(LIBS) $(WRAPFLAGS) $(LDFLAGS) $(GMONLDOPT) -rdynamic -o $@


#
# Clean the most, except generated c files
subclean:
	$(Q) $(RM) $(obj)/*.{gcda,gcno,gcov}
	$(Q) $(RM) $(obj)/pie/*.{gcda,gcno,gcov}
	$(Q) $(RM) -r $(obj)/gcov
	$(Q) $(MAKE) $(build)=$(ARCH_DIR) clean
	$(Q) $(MAKE) $(call build-as,Makefile.library,$(PIE_DIR)) clean
	$(Q) $(MAKE) $(call build-as,Makefile.crtools,criu) clean
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
.PHONY: install

uninstall:
	$(E) " UNINSTALL" criu
	$(Q) $(RM) $(addprefix $(DESTDIR)$(SBINDIR)/,criu)
	$(Q) $(RM) $(addprefix $(DESTDIR)$(INCLUDEDIR)/criu/,$(notdir $(UAPI_HEADERS)))
	$(Q) $(RM) $(addprefix $(DESTDIR)$(LIBEXECDIR)/criu/scripts/,systemd-autofs-restart.sh)
.PHONY: uninstall

all-y += check-packages $(obj)/criu
