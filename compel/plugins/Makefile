.PHONY: .FORCE

CFLAGS			:= $(filter-out -pg $(CFLAGS-GCOV),$(CFLAGS)) -DCR_NOGLIBC
PLUGIN_ARCH_DIR		:= compel/arch/$(ARCH)/plugins

#
# CFLAGS, ASFLAGS, LDFLAGS

#
# UAPI inclusion, referred as <compel/...>
ccflags-y		+= -I compel/include/uapi
ccflags-y		+= -I compel/plugins/include/uapi
asflags-y		+= -I compel/include/uapi
asflags-y		+= -I compel/plugins/include/uapi

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
# Fds plugin
target			+= fds
fds-obj-y		+= fds/fds.o

#
# Shmem plugin
target			+= shmem
shmem-obj-y		+= shmem/shmem.o

#
# STD plugin
target			+= std
std-obj-y		+= std/std.o
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
