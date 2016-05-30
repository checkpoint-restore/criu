include $(SRC_DIR)/Makefile.versions

ccflags-y	+= -iquote criu/include
ccflags-y	+= -iquote compel/include
ccflags-y	+= -iquote compel/arch/$(ARCH)/include
ccflags-y	+= -DCOMPEL_VERSION=\"$(COMPEL_SO_VERSION_MAJOR).$(COMPEL_SO_VERSION_MINOR)\"

host-ccflags-y	+= $(filter-out -pg $(CFLAGS-GCOV),$(ccflags-y))
HOSTCFLAGS	+= $(filter-out -pg $(CFLAGS-GCOV),$(WARNINGS) $(DEFINES))
HOSTLDFLAGS	+= $(filter-out -pg $(CFLAGS-GCOV),$(LDFLAGS))
HOSTCFLAGS	:= $(filter-out -DCONFIG_X86_64,$(HOSTCFLAGS))
export host-ccflags-y HOSTCFLAGS HOSTLDFLAGS

hostprogs-y	+= compel
compel-objs	+= main.o
compel-objs	+= handle-elf.o
compel-objs	+= arch/$(ARCH)/handle-elf.o

ifeq ($(ARCH),x86)
# Add -DCONFIG_X86_64 or -DCONFIG_X86_32 to HOSTCFLAGS
define ccflags-defines
        export HOSTCFLAGS_$(notdir $(1)) += -DCONFIG_X86_64
endef
$(eval $(call map,ccflags-defines,$(compel-objs)))

compel-objs += handle-elf-32.o
export HOSTCFLAGS_handle-elf-32.o += -DCONFIG_X86_32
endif # ARCH == x86

.PHONY: .FORCE

export compel-objs
test/compel/%: .FORCE
	$(Q) $(MAKE) $(build)=test/compel $@

test: test/compel/test_handle_binary

.PHONY: test
