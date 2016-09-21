include $(SRC_DIR)/Makefile.versions

.PHONY: .FORCE

COMPEL_SO_VERSION	:= $(COMPEL_SO_VERSION_MAJOR)$(if $(COMPEL_SO_VERSION_MINOR),.$(COMPEL_SO_VERSION_MINOR))$(if $(COMPEL_SO_VERSION_SUBLEVEL),.$(COMPEL_SO_VERSION_SUBLEVEL))
COMPEL_SO_VERSION_CODE	:= $(shell expr $(COMPEL_SO_VERSION_MAJOR) \* 65536 \+ $(COMPEL_SO_VERSION_MINOR) \* 256 \+ $(COMPEL_SO_VERSION_SUBLEVEL))
ccflags-y		+= -iquote compel/arch/$(ARCH)/src/lib/include
ccflags-y		+= -iquote compel/include
ccflags-y		+= -iquote compel/plugins/include
ccflags-y		+= -iquote $(SRC_DIR)/criu/include
ccflags-y		+= -fPIC

lib-y			+= arch/$(ARCH)/src/lib/handle-elf.o
lib-y			+= src/lib/handle-elf.o
lib-y			+= src/lib/handle-elf-32.o

obj-y			+= src/main.o

CFLAGS_handle-elf-32.o += -UCONFIG_X86_64 -DCONFIG_X86_32
CFLAGS_handle-elf-32.d += -UCONFIG_X86_64 -DCONFIG_X86_32

cleanup-y		+= compel/compel
cleanup-y		+= compel/libcompel.so
