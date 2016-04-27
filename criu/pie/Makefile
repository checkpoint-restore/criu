# native/compat target names are _only_ for parasite
# restorer is always native (64-bit)
parasite_target		:= native

ifeq ($(ARCH),x86)
        parasite_target	+= compat
endif

native-obj-y           += parasite.o
compat-obj-y           += compat/parasite-compat.o

restorer-obj-y		+= restorer.o
restorer-obj-y		+= ./$(ARCH_DIR)/restorer.o

ifeq ($(ARCH),x86)
        restorer-obj-e		+= ./$(ARCH_DIR)/syscalls-64.built-in.o

        native-obj-y		+= ./$(ARCH_DIR)/parasite-head-64.o
        native-obj-e		+= ./$(ARCH_DIR)/syscalls-64.built-in.o
        compat-obj-y		+= ./$(ARCH_DIR)/parasite-head-32.o
        compat-obj-e		+= ./$(ARCH_DIR)/syscalls-32.built-in.o

        AFLAGS_parasite-head-64.o += -fpie -DCONFIG_X86_64
        AFLAGS_parasite-head-64.d += -fpie -DCONFIG_X86_64

        AFLAGS_parasite-head-32.o += -fno-pic -m32 -DCONFIG_X86_32
        AFLAGS_parasite-head-32.d += -fno-pic -m32 -DCONFIG_X86_32
else
        native-obj-y		+= ./$(ARCH_DIR)/parasite-head.o
        native-obj-e		+= ./$(ARCH_DIR)/syscalls.built-in.o
        restorer-obj-e		+= ./$(ARCH_DIR)/syscalls.built-in.o
endif

target			+= $(parasite_target) restorer

#
# We can't provide proper mount implementation
# in parasite code -- it requires run-time rellocation
# applications, which is not the target of the
# project.
#
CFLAGS			:= $(filter-out -pg $(CFLAGS-GCOV),$(CFLAGS))
CFLAGS			:= $(filter-out -DCONFIG_X86_64,$(CFLAGS))
CFLAGS			+= -iquote $(SRC_DIR)/compel/include
CFLAGS			+= -iquote $(SRC_DIR)/criu/arch/$(ARCH)/include
CFLAGS			+= -iquote $(SRC_DIR)/criu/include
CFLAGS			+= -iquote $(SRC_DIR)/include
CFLAGS			+= -iquote $(SRC_DIR)
CFLAGS			+= -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0
CFLAGS			+= -Wp,-U_FORTIFY_SOURCE -Wp,-D_FORTIFY_SOURCE=0


ccflags-y		+= -DCR_NOGLIBC
NATIVE_CFLAGS		:= $(shell $(SRC_DIR)/compel/compel --arch=$(ARCH) cflags)

ifeq ($(ARCH),x86)
        NATIVE_CFLAGS	+= -DCONFIG_X86_64
        COMPAT_CFLAGS	+= -fno-pic -m32 -DCONFIG_X86_32
        COMPAT_LDFLAGS	+= -m elf_i386
endif

CFLAGS_restorer.o	+= $(NATIVE_CFLAGS)
# $1 - object name
define obj-export-native-flags
        CFLAGS_$(notdir $(1))	:= $(NATIVE_CFLAGS)
endef
# $1 - object name
define obj-export-compat-flags
        CFLAGS_$(notdir $(1))	:= $(COMPAT_CFLAGS)
        LDFLAGS_$(notdir $(1))	:= $(COMPAT_LDFLAGS)
endef

$(eval $(call map,obj-export-native-flags,$(native-obj-y) native))
$(eval $(call map,obj-export-compat-flags,$(compat-obj-y) compat))

ifeq ($(SRCARCH),arm)
        ccflags-y	+= -marm
endif

asflags-y		+= -D__ASSEMBLY__

GEN-OFFSETS		:= $(obj)/../../scripts/gen-offsets.sh

BLOBS			+= $(obj)/restorer-blob.h

define gen-pields-blobs-var
PIELDS			+= $(obj)/pie.lds-$(1).S
BLOBS			+= $(obj)/parasite-$(1)-blob.h
endef
$(eval $(call map,gen-pields-blobs-var,$(parasite_target)))

.SECONDARY:

ifeq ($(piegen-y),y)
PIELDS_INCLUDE		:= $(obj)/pie-reloc.lds.S.in
else
PIELDS_INCLUDE		:= $(obj)/pie.lds.S.in
endif

ifeq ($(ARCH),x86)
$(obj)/pie.lds-native.S: $(PIELDS_INCLUDE)
	$(call msg-gen, $@)
	$(Q) echo "OUTPUT_ARCH(i386:x86-64)"		>  $@
	$(Q) echo "TARGET(elf64-x86-64)"		>> $@
	$(Q) cat $<					>> $@

$(obj)/pie.lds-compat.S: $(PIELDS_INCLUDE)
	$(call msg-gen, $@)
	$(Q) echo "OUTPUT_ARCH(i386)"			>  $@
	$(Q) echo "TARGET(elf32-i386)"			>> $@
	$(Q) cat $<					>> $@
else # !x86
ifeq ($(filter-out i386 ia32,$(ARCH)),)
$(PIELDS): $(PIELDS_INCLUDE)
	$(call msg-gen, $@)
	$(Q) echo "OUTPUT_ARCH(i386)"			>  $@
	$(Q) echo "TARGET(elf32-i386)"			>> $@
	$(Q) cat $<					>> $@
else # arm, aarch64, ppc64
$(PIELDS): $(PIELDS_INCLUDE)
	$(call msg-gen, $@)
	$(Q) echo "OUTPUT_ARCH($(LDARCH))"              >  $@
	$(Q) cat $<					>> $@
endif # non i386
endif # non x86 ARCH

# for C files, we need "parasite-native" to be "parasite_native"
target-name = $(patsubst criu/pie/%_blob.h,%,$(subst -,_,$(1)))

ifeq ($(piegen-y),y)
ifeq ($(strip $(V)),)
        piegen_stdout := >/dev/null
endif

$(obj)/restorer.built-in.bin.o: $(obj)/restorer.built-in.o		\
				$(obj)/native.lib.a $(obj)/pie.lds-native.S
	$(call msg-gen, $@)
	$(Q) $(LD) -r -T $(obj)/pie.lds-native.S -o $@ $< $(obj)/native.lib.a

# $1 - binary mode: native/compat
define gen-rule-built-in.bin.o
$(obj)/parasite-$(1).built-in.bin.o: $(obj)/$(1).built-in.o		\
				$(obj)/$(1).lib.a $(obj)/pie.lds-$(1).S
	$$(call msg-gen, $$@)
	$(Q) $(LD) -r -T $(obj)/pie.lds-$(1).S -o $$@ $$< $(obj)/$(1).lib.a
endef
$(eval $(call map,gen-rule-built-in.bin.o,$(parasite_target)))

$(obj)/%-blob.h: $(obj)/%.built-in.bin.o $(SRC_DIR)/compel/compel
	$(call msg-gen, $@)
	$(Q) $(SRC_DIR)/compel/compel piegen -f $<			\
		-v $(call target-name,$@)_relocs			\
		-p $(call target-name,$@)_blob_offset__			\
		-s $(call target-name,$@)_blob				\
		-r $(call target-name,$@)_nr_gotpcrel			\
		-u $(SRC_DIR)/compel/include/uapi			\
		-o $@ $(piegen_stdout)

else # !piegen-y

# ld on arm doesn't like -pie and -r options together
ifeq ($(filter arm aarch64,$(ARCH)),)
        LD_R := -r
endif

define gen-rule-built-in.bin.o
$(obj)/parasite-$(1).built-in.bin.o: $(obj)/$(1).built-in.o		\
				$(obj)/pie.lds-$(1).S $(obj)/native.lib.a
	$$(call msg-gen, $$@)
	$(Q) $(LD) $(LD_R) -T $(obj)/pie.lds-$(1).S -o $$@ $$< $(obj)/native.lib.a
endef

$(eval $(call map,gen-rule-built-in.bin.o,$(parasite_target)))

$(obj)/restorer.built-in.bin.o: $(obj)/restorer.built-in.o		\
				$(obj)/pie.lds-native.S $(obj)/native.lib.a
	$(call msg-gen, $@)
	$(Q) $(LD) $(LD_R) -T $(obj)/pie.lds-native.S -o $@ $< $(obj)/native.lib.a

$(obj)/%.built-in.bin: $(obj)/%.built-in.bin.o
	$(call msg-gen, $@)
	$(Q) $(OBJCOPY) -O binary $^ $@

$(obj)/%-blob.h: $(obj)/%.built-in.bin $(GEN-OFFSETS)
	$(call msg-gen, $@)
	$(Q) $(SH) $(GEN-OFFSETS) $(@:-blob.h=) $(call target-name,$@) $(CROSS_COMPILE) > $@


endif # !piegen-y

all-y += $(BLOBS)
# blobs and pields are in cleanup, rather than in mrproper because
# we want them to be re-generated after `make clean && make`
cleanup-y += $(BLOBS)
cleanup-y += $(PIELDS)
cleanup-y += $(obj)/*.bin
cleanup-y += $(obj)/*.built-in.bin.o
cleanup-y += $(obj)/*.built-in.bin
