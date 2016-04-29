include $(SRC_DIR)/Makefile.versions

ccflags-y	+= -iquote criu/include
ccflags-y	+= -iquote compel/include
ccflags-y	+= -iquote compel/arch/$(ARCH)/include
ccflags-y	+= -DCOMPEL_VERSION=\"$(COMPEL_SO_VERSION_MAJOR).$(COMPEL_SO_VERSION_MINOR)\"

host-ccflags-y	+= $(filter-out -pg $(CFLAGS-GCOV),$(ccflags-y))
HOSTCFLAGS	+= $(filter-out -pg $(CFLAGS-GCOV),$(WARNINGS) $(DEFINES))
HOSTLDFLAGS	+= $(filter-out -pg $(CFLAGS-GCOV),$(LDFLAGS))

hostprogs-y	+= compel
compel-objs	+= main.o
compel-objs	+= handle-elf.o
compel-objs	+= arch/$(ARCH)/handle-elf.o

# Add $(DEFINES) to CFLAGS of compel-objs.
# We can't do ccflags-y += $(DEFINES)
# as we need to build handle-elf-32.o
# with -DCONFIG_X86_32
define ccflags-defines
        HOSTCFLAGS_$(notdir $(1)) += $(DEFINES)
endef
$(eval $(call map,ccflags-defines,$(compel-objs)))

ifeq ($(ARCH),x86)
        compel-objs += handle-elf-32.o
        HOSTCFLAGS_handle-elf-32.o += -DCONFIG_X86_32
endif
