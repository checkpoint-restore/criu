include Makefile.versions

COMPEL_SO_VERSION	:= $(COMPEL_SO_VERSION_MAJOR)$(if $(COMPEL_SO_VERSION_MINOR),.$(COMPEL_SO_VERSION_MINOR))$(if $(COMPEL_SO_VERSION_SUBLEVEL),.$(COMPEL_SO_VERSION_SUBLEVEL))
COMPEL_SO_VERSION_CODE	:= $(shell expr $(COMPEL_SO_VERSION_MAJOR) \* 65536 \+ $(COMPEL_SO_VERSION_MINOR) \* 256 \+ $(COMPEL_SO_VERSION_SUBLEVEL))
ccflags-y		+= -DINCLUDEDIR=\"$(INCLUDEDIR)\"
ccflags-y		+= -DLIBEXECDIR=\"$(LIBEXECDIR)\"
ccflags-y		+= -DLIBDIR=\"$(LIBDIR)\"
ccflags-y		+= -DSTATIC_LIB=\"$(LIBCOMPEL_A)\"
ccflags-y		+= -DDYN_LIB=\"$(LIBCOMPEL_SO).$(COMPEL_SO_VERSION_MAJOR)\"
ccflags-y		+= -iquote compel/arch/$(ARCH)/src/lib/include
ccflags-y		+= -iquote compel/include
ccflags-y		+= -fno-strict-aliasing
ccflags-y		+= -fPIC
ccflags-y		+= $(CFLAGS_PIE)
ldflags-y		+= -r

#
# UAPI inclusion, referred as <compel/...>
ccflags-y		+= -I compel/include/uapi

lib-name		:= $(LIBCOMPEL_A)
lib-y			+= src/lib/log.o
host-lib-y		+= src/lib/log.o

lib-y			+= arch/$(ARCH)/src/lib/cpu.o
lib-y			+= arch/$(ARCH)/src/lib/infect.o
lib-y			+= src/lib/infect-rpc.o
lib-y			+= src/lib/infect-util.o
lib-y			+= src/lib/infect.o
lib-y			+= src/lib/ptrace.o

# handle_elf() has no support of ELF relocations on ARM (yet?)
ifneq ($(filter arm aarch64,$(ARCH)),)
CFLAGS			+= -DNO_RELOCS
HOSTCFLAGS		+= -DNO_RELOCS
endif

obj-y			+= src/main.o
obj-y			+= arch/$(ARCH)/src/lib/handle-elf.o
obj-y			+= src/lib/handle-elf.o

host-ccflags-y		+= $(ccflags-y)

hostprogs-y		+= compel-host-bin
compel-host-bin-objs	:= $(patsubst %.o,%-host.o,$(obj-y) $(host-lib-y))

cleanup-y		+= compel/compel
cleanup-y		+= compel/compel-host-bin
cleanup-y		+= compel/libcompel.so

install: compel/compel compel/$(LIBCOMPEL_SO) compel/$(LIBCOMPEL_A)
	$(E) "  INSTALL " compel
	$(Q) mkdir -p $(DESTDIR)$(BINDIR)
	$(Q) install -m 755 compel/compel $(DESTDIR)$(BINDIR)
	$(E) "  INSTALL " $(LIBCOMPEL_SO)
	$(Q) mkdir -p $(DESTDIR)$(LIBDIR)
	$(Q) install -m 0644 compel/$(LIBCOMPEL_SO) $(DESTDIR)$(LIBDIR)
	$(Q) install -m 755 compel/$(LIBCOMPEL_SO) $(DESTDIR)$(LIBDIR)/$(LIBCOMPEL_SO).$(COMPEL_SO_VERSION_MAJOR).$(COMPEL_SO_VERSION_MINOR)
	$(Q) ln -fns $(LIBCOMPEL_SO).$(COMPEL_SO_VERSION_MAJOR).$(COMPEL_SO_VERSION_MINOR) $(DESTDIR)$(LIBDIR)/$(LIBCOMPEL_SO).$(COMPEL_SO_VERSION_MAJOR)
	$(Q) ln -fns $(LIBCOMPEL_SO).$(COMPEL_SO_VERSION_MAJOR).$(COMPEL_SO_VERSION_MINOR) $(DESTDIR)$(LIBDIR)/$(LIBCOMPEL_SO)
	$(E) "  INSTALL " $(LIBCOMPEL_A)
	$(Q) install -m 0644 compel/$(LIBCOMPEL_A) $(DESTDIR)$(LIBDIR)
	$(E) "  INSTALL " compel uapi
	$(Q) mkdir -p $(DESTDIR)$(INCLUDEDIR)/compel/asm
	$(Q) cp -fr compel/include/uapi/*.h $(DESTDIR)$(INCLUDEDIR)/compel/
	$(Q) cp -fr compel/include/uapi/asm/*.h $(DESTDIR)$(INCLUDEDIR)/compel/asm/
	$(Q) mkdir -p $(DESTDIR)$(INCLUDEDIR)/compel/common/asm
	$(Q) cp -fr include/common/compiler.h $(DESTDIR)$(INCLUDEDIR)/compel/common/
.PHONY: install

uninstall:
	$(E) " UNINSTALL" compel
	$(Q) $(RM) $(addprefix $(DESTDIR)$(BINDIR)/,compel)
	$(E) " UNINSTALL" $(LIBCOMPEL_SO)
	$(Q) $(RM) $(addprefix $(DESTDIR)$(LIBDIR)/,$(LIBCOMPEL_SO))
	$(Q) $(RM) $(addprefix $(DESTDIR)$(LIBDIR)/,$(LIBCOMPEL_SO).$(COMPEL_SO_VERSION_MAJOR))
	$(Q) $(RM) $(addprefix $(DESTDIR)$(LIBDIR)/,$(LIBCOMPEL_SO).$(COMPEL_SO_VERSION_MAJOR).$(COMPEL_SO_VERSION_MINOR))
	$(E) " UNINSTALL" $(LIBCOMPEL_A)
	$(Q) $(RM) $(addprefix $(DESTDIR)$(LIBDIR)/,$(LIBCOMPEL_A))
	$(E) " UNINSTALL" compel uapi
	$(Q) $(RM) -rf $(addprefix $(DESTDIR)$(INCLUDEDIR)/,compel/*)
.PHONY: uninstall
