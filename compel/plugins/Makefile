CFLAGS		:= $(filter-out -pg $(CFLAGS-GCOV) $(CFLAGS-ASAN),$(CFLAGS))
CFLAGS		+= -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0
CFLAGS		+= -Wp,-U_FORTIFY_SOURCE -Wp,-D_FORTIFY_SOURCE=0

PLUGIN_ARCH_DIR		:= compel/arch/$(ARCH)/plugins

#
# CFLAGS, ASFLAGS, LDFLAGS

# Required for pie code
ccflags-y		+= $(CFLAGS_PIE)

# UAPI inclusion, referred as <compel/...>
ccflags-y		+= -I compel/include/uapi
asflags-y		+= -I compel/include/uapi

# General compel includes
ccflags-y		+= -iquote compel/include

ifeq ($(ARCH),mips)
ccflags-y		+= -mno-abicalls -fno-pic -fno-stack-protector
else
ccflags-y		+= -fpie -fno-stack-protector
endif

# General compel/plugins includes
ccflags-y		+= -iquote $(obj)/include
asflags-y		+= -iquote $(obj)/include

# Arch compel/plugins includes
ccflags-y		+= -iquote $(PLUGIN_ARCH_DIR)/include
asflags-y		+= -iquote $(PLUGIN_ARCH_DIR)/include
asflags-y		+= -iquote $(PLUGIN_ARCH_DIR)

# General flags for assembly
ifeq ($(ARCH),mips)
asflags-y		+= -mno-abicalls -fno-pic -Wstrict-prototypes
else
asflags-y		+= -fpie -Wstrict-prototypes
endif

asflags-y		+= -nostdlib -fomit-frame-pointer
asflags-y		+= -fno-stack-protector
ldflags-y		+= -z noexecstack

#
# Shmem plugin
target			+= shmem
shmem-lib-y		+= shmem/shmem.o

#
# STD plugin
target			+= std
std-lib-y		+= std/std.o
std-lib-y		+= std/fds.o
std-lib-y		+= std/log.o
std-lib-y		+= std/string.o
std-lib-y		+= std/infect.o
std-lib-y		+= ./$(PLUGIN_ARCH_DIR)/std/parasite-head.o

#
# FDS plugin
target			+= fds
fds-lib-y		+= fds/fds.o

ifeq ($(ARCH),x86)
	std-lib-y	+= ./$(PLUGIN_ARCH_DIR)/std/memcpy.o
endif

ifeq ($(ARCH),mips)
	std-lib-y	+= ./$(PLUGIN_ARCH_DIR)/std/memcpy.o
endif

ifeq ($(ARCH),ppc64)
	std-lib-y	+= ./$(PLUGIN_ARCH_DIR)/std/memcpy.o
	std-lib-y	+= ./$(PLUGIN_ARCH_DIR)/std/memcmp.o
endif

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
$(foreach t,$(target),$(eval $(call syscall-priority,$(t)-lib-y,std-headers-deps)))

#
# FIXME syscall-types.h should be setup earlier
#
install: compel/plugins/std.lib.a compel/plugins/fds.lib.a
	$(E) "  INSTALL " compel plugins
	$(Q) mkdir -p $(DESTDIR)$(LIBEXECDIR)/compel/
	$(Q) install -m 0644 $^ $(DESTDIR)$(LIBEXECDIR)/compel/
	$(Q) mkdir -p $(DESTDIR)$(LIBEXECDIR)/compel/scripts
	$(Q) install -m 0644 compel/arch/$(ARCH)/scripts/compel-pack.lds.S $(DESTDIR)$(LIBEXECDIR)/compel/scripts
	$(E) "  INSTALL " compel plugins uapi
	$(Q) mkdir -p $(DESTDIR)$(INCLUDEDIR)/compel/plugins/std/asm
	$(Q) cp -fL compel/plugins/include/uapi/*.h $(DESTDIR)$(INCLUDEDIR)/compel/plugins/
	$(Q) cp -fL compel/plugins/include/uapi/std/*.h $(DESTDIR)$(INCLUDEDIR)/compel/plugins/std/
	$(Q) cp -fL compel/plugins/include/uapi/std/asm/*.h $(DESTDIR)$(INCLUDEDIR)/compel/plugins/std/asm/
.PHONY: install

uninstall:
	$(E) " UNINSTALL" compel plugins
	$(Q) $(RM) $(addprefix $(DESTDIR)$(LIBEXECDIR)/compel/,*.lib.a)
	$(Q) $(RM) $(addprefix $(DESTDIR)$(LIBEXECDIR)/compel/scripts/,compel-pack.lds.S)
	$(E) " UNINSTALL" compel and plugins uapi
	$(Q) $(RM) -rf $(addprefix $(DESTDIR)$(INCLUDEDIR)/,compel/plugins)
.PHONY: uninstall
