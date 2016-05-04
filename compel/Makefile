include $(SRC_DIR)/Makefile.versions

ccflags-y	+= -iquote criu/include
ccflags-y	+= -iquote compel/include
ccflags-y	+= -iquote compel/arch/$(ARCH)/include
ccflags-y	+= -DCOMPEL_VERSION=\"$(COMPEL_SO_VERSION_MAJOR).$(COMPEL_SO_VERSION_MINOR)\"

host-ccflags-y	+= $(filter-out -pg $(CFLAGS-GCOV),$(ccflags-y))
HOSTCFLAGS	+= $(filter-out -pg $(CFLAGS-GCOV),$(WARNINGS) $(filter-out -DCONFIG_X86_64,$(DEFINES)))
HOSTLDFLAGS	+= $(filter-out -pg $(CFLAGS-GCOV),$(LDFLAGS))

hostprogs-y	+= compel
compel-objs	+= main.o
compel-objs	+= handle-elf.o
compel-objs	+= arch/$(ARCH)/handle-elf.o

ifeq ($(ARCH),x86)
# Add -DCONFIG_X86_64 or -DCONFIG_X86_32 to HOSTCFLAGS
define ccflags-defines
        HOSTCFLAGS_$(notdir $(1)) += -DCONFIG_X86_64
endef
$(eval $(call map,ccflags-defines,$(compel-objs)))

compel-objs += handle-elf-32.o
HOSTCFLAGS_handle-elf-32.o += -DCONFIG_X86_32
endif # ARCH == x86
