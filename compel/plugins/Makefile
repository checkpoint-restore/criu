.PHONY: .FORCE

CFLAGS			:= $(filter-out -pg $(CFLAGS-GCOV),$(CFLAGS)) -DCR_NOGLIBC
PLUGIN_ARCH_DIR		:= compel/arch/$(ARCH)/plugins

#
# CFLAGS, ASFLAGS, LDFLAGS

#
# UAPI inclusion, referred as <compel/...>
ccflags-y		+= -I compel/include/uapi
asflags-y		+= -I compel/include/uapi

# General compel includes
ccflags-y		+= -iquote $(SRC_DIR)/compel/include
ccflags-y		+= -fpie -fno-stack-protector

# General compel/plugins includes
ccflags-y		+= -iquote $(obj)/include
ccflags-y		+= -iquote $(obj)/include/uapi
asflags-y		+= -iquote $(obj)/include
asflags-y		+= -iquote $(obj)/include/uapi

# Arch compel/plugins includes
ccflags-y		+= -iquote $(PLUGIN_ARCH_DIR)/include
asflags-y		+= -iquote $(PLUGIN_ARCH_DIR)/include
asflags-y		+= -iquote $(PLUGIN_ARCH_DIR)

# General flags for assembly
asflags-y		+= -fpie -Wstrict-prototypes
asflags-y		+= -D__ASSEMBLY__ -nostdlib -fomit-frame-pointer
asflags-y		+= -fno-stack-protector
ldflags-y		+= -z noexecstack

#
# Shmem plugin
target			+= shmem
shmem-obj-y		+= shmem/shmem.o

#
# STD plugin
target			+= std
std-obj-y		+= std/std.o
std-obj-y		+= std/fds.o
std-obj-y		+= std/log.o
std-obj-y		+= std/string.o
std-obj-y		+= std/infect.o
std-obj-y		+= ./$(PLUGIN_ARCH_DIR)/std/parasite-head.o

include ./$(PLUGIN_ARCH_DIR)/std/syscalls/Makefile.syscalls

define syscall-priority
$(addprefix $(obj)/,$($(1):%.o=%.d)): | $($(2))
$(addprefix $(obj)/,$($(1):%.o=%.i)): | $($(2))
$(addprefix $(obj)/,$($(1):%.o=%.s)): | $($(2))
$(addprefix $(obj)/,$($(1))): | $($(2))
endef

#
# Almost all plugins depen on syscall headers
# and definitions so we have to order their
# generation manually.
$(foreach t,$(target),$(eval $(call syscall-priority,$(t)-obj-y,std-headers-deps)))

#
# FIXME syscall-types.h should be setup earlier
#
install: compel/plugins/std.built-in.o
	$(E) "  INSTALL " compel plugins
	$(Q) mkdir -p $(DESTDIR)$(LIBEXECDIR)/compel/
	$(Q) install -m 0644 compel/plugins/std.built-in.o $(DESTDIR)$(LIBEXECDIR)/compel/
	$(Q) mkdir -p $(DESTDIR)$(LIBEXECDIR)/compel/scripts
	$(Q) install -m 0644 compel/arch/$(ARCH)/scripts/compel-pack.lds.S $(DESTDIR)$(LIBEXECDIR)/compel/scripts
	$(E) "  INSTALL " compel plugins uapi
	$(Q) mkdir -p $(DESTDIR)$(INCLUDEDIR)/compel/plugins/std/asm
	$(Q) cp -fr compel/include/uapi/compel/plugins/plugin-std.h $(DESTDIR)$(INCLUDEDIR)/compel/plugins
	$(Q) cp -fr compel/include/uapi/compel/plugins/std/*.h $(DESTDIR)$(INCLUDEDIR)/compel/plugins/std
	$(Q) cp -fr compel/arch/$(ARCH)/plugins/include/asm/syscall-types.h $(DESTDIR)$(INCLUDEDIR)/compel/plugins/std/asm
.PHONY: install

uninstall:
	$(E) " UNINSTALL" compel plugins
	$(Q) $(RM) $(addprefix $(DESTDIR)$(LIBEXECDIR)/compel/,std.built-in.o)
	$(Q) $(RM) $(addprefix $(DESTDIR)$(LIBEXECDIR)/compel/scripts,compel-pack.lds.S)
	$(E) " UNINSTALL" compel and plugins uapi
	$(Q) $(RM) -rf $(addprefix $(DESTDIR)$(INCLUDEDIR),compel/plugins)
.PHONY: uninstall
