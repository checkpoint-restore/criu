include $(SRC_DIR)/Makefile.versions

.PHONY: .FORCE

COMPEL_SO_VERSION	:= $(COMPEL_SO_VERSION_MAJOR)$(if $(COMPEL_SO_VERSION_MINOR),.$(COMPEL_SO_VERSION_MINOR))$(if $(COMPEL_SO_VERSION_SUBLEVEL),.$(COMPEL_SO_VERSION_SUBLEVEL))
COMPEL_SO_VERSION_CODE	:= $(shell expr $(COMPEL_SO_VERSION_MAJOR) \* 65536 \+ $(COMPEL_SO_VERSION_MINOR) \* 256 \+ $(COMPEL_SO_VERSION_SUBLEVEL))
ccflags-y		+= -iquote compel/arch/$(ARCH)/src/lib/include
ccflags-y		+= -iquote compel/include
ccflags-y		+= -iquote compel/plugins/include
ccflags-y		+= -fPIC

#
# UAPI inclusion, referred as <compel/...>
ccflags-y		+= -I compel/include/uapi
ccflags-y		+= -I compel/plugins/include/uapi

lib-name		:= libcompel.a
lib-y			+= arch/$(ARCH)/src/lib/handle-elf.o
host-lib-y		+= arch/$(ARCH)/src/lib/handle-elf.o
lib-y			+= src/lib/handle-elf.o
host-lib-y		+= src/lib/handle-elf.o
lib-y			+= src/lib/log.o
host-lib-y		+= src/lib/log.o

lib-y			+= arch/$(ARCH)/src/lib/cpu.o

ifeq ($(ARCH),x86)
lib-y			+= src/lib/handle-elf-32.o
host-lib-y		+= src/lib/handle-elf-32.o
endif

obj-y			+= src/main.o

ifeq ($(ARCH),x86)
CFLAGS_handle-elf-32.o += -UCONFIG_X86_64 -DCONFIG_X86_32
CFLAGS_handle-elf-32.d += -UCONFIG_X86_64 -DCONFIG_X86_32
endif

host-ccflags-y		+= $(ccflags-y)

hostprogs-y		+= compel-host
compel-host-objs	:= $(patsubst %.o,%-host.o,$(obj-y) $(host-lib-y))

ifeq ($(ARCH),x86)
HOSTCFLAGS_handle-elf-32-host.o += -UCONFIG_X86_64 -DCONFIG_X86_32
HOSTCFLAGS_handle-elf-32-host.d += -UCONFIG_X86_64 -DCONFIG_X86_32
endif

cleanup-y		+= compel/compel
cleanup-y		+= compel/compel-host
cleanup-y		+= compel/libcompel.so
