# native/compat target names are _only_ for parasite
# restorer is always native (64-bit)
parasite_target		:= native

ifeq ($(CONFIG_COMPAT),y)
        parasite_target	+= compat
endif

compel_pack_lds-native	:= $(SRC_DIR)/compel/arch/$(ARCH)/scripts/compel-pack.lds.S
compel_pack_lds-compat	:= $(SRC_DIR)/compel/arch/$(ARCH)/scripts/compel-pack-compat.lds.S
compel_std-native	:= $(SRC_DIR)/compel/plugins/std.built-in.o
compel_std-compat	:= $(SRC_DIR)/compel/plugins/std-compat.built-in.o

native-obj-y           += parasite.o
compat-obj-y           += compat/parasite-compat.o

restorer-obj-y		+= restorer.o
restorer-obj-y		+= ./$(ARCH_DIR)/restorer.o

ifeq ($(ARCH),x86)
        restorer-obj-e		+= ./compel/plugins/std.built-in.o

        ifeq ($(CONFIG_COMPAT),y)
                restorer-obj-y	+= ./$(ARCH_DIR)/call32.o
                restorer-obj-y	+= ./$(ARCH_DIR)/sigaction_compat_pie.o
        endif

        native-obj-e		+= ./compel/plugins/std.built-in.o
        compat-obj-e		+= ./compel/plugins/std-compat.built-in.o
else
        native-obj-e		+= ./compel/plugins/std.built-in.o
        restorer-obj-e		+= ./compel/plugins/std.built-in.o
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
CFLAGS			+= -iquote $(SRC_DIR)/criu/arch/$(ARCH)/include
CFLAGS			+= -iquote $(SRC_DIR)/criu/include
CFLAGS			+= -iquote $(SRC_DIR)/include
CFLAGS			+= -iquote $(SRC_DIR)
CFLAGS			+= -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0
CFLAGS			+= -Wp,-U_FORTIFY_SOURCE -Wp,-D_FORTIFY_SOURCE=0

ccflags-y		+= -I compel/include/uapi
ccflags-y		+= -I compel/plugins/include/uapi
ccflags-y		+= -DCR_NOGLIBC
ccflags-y		+= -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0
ifneq ($(filter-out clean mrproper,$(MAKECMDGOALS)),)
NATIVE_CFLAGS		:= $(shell $(SRC_DIR)/compel/compel-host --arch=$(ARCH) cflags)
ifeq ($(ARCH),x86)
        COMPAT_CFLAGS	:= $(shell $(SRC_DIR)/compel/compel-host --arch=ia32 cflags)
endif
endif

ifeq ($(ARCH),x86)
        NATIVE_CFLAGS	+= -DCONFIG_X86_64
        COMPAT_CFLAGS	+= -m32 -DCONFIG_X86_32
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

$(eval $(call map,obj-export-native-flags,$(restorer-obj-y)))
$(eval $(call map,obj-export-native-flags,$(native-obj-y) native))
$(eval $(call map,obj-export-compat-flags,$(compat-obj-y) compat))

ifeq ($(SRCARCH),arm)
        ccflags-y	+= -marm
endif

asflags-y		+= -D__ASSEMBLY__

GEN-OFFSETS		:= $(obj)/../../scripts/gen-offsets.sh

BLOBS			+= $(obj)/restorer-blob.h

define gen-pields-blobs-var
BLOBS			+= $(obj)/parasite-$(1)-blob.h
endef
$(eval $(call map,gen-pields-blobs-var,$(parasite_target)))

.SECONDARY:

# for C files, we need "parasite-native" to be "parasite_native"
target-name = $(patsubst criu/pie/%_blob.h,%,$(subst -,_,$(1)))

ifeq ($(piegen-y),y)
ifeq ($(strip $(V)),)
        piegen_stdout := >/dev/null
endif

$(obj)/restorer.built-in.o: $(compel_std-native)
$(obj)/restorer.built-in.bin.o: $(obj)/restorer.built-in.o		\
				$(obj)/native.lib.a $(compel_pack_lds-native)
	$(call msg-gen, $@)
	$(Q) $(LD) -r -T $(compel_pack_lds-native) -o $@ $< $(obj)/native.lib.a

# $1 - binary mode: native/compat
define gen-rule-built-in.bin.o
$(obj)/$(1).built-in.o: $(compel_std-$(1))
$(obj)/parasite-$(1).built-in.bin.o: $(obj)/$(1).built-in.o		\
				$(obj)/$(1).lib.a $(compel_pack_lds-$(1))
	$$(call msg-gen, $$@)
	$(Q) $(LD) -r -T $(compel_pack_lds-$(1)) -o $$@ $$< $(obj)/$(1).lib.a
endef
$(eval $(call map,gen-rule-built-in.bin.o,$(parasite_target)))

$(obj)/%-blob.h: $(obj)/%.built-in.bin.o $(SRC_DIR)/compel/compel-host
	$(call msg-gen, $@)
	$(Q) $(SRC_DIR)/compel/compel-host piegen -f $<			\
		-l 4							\
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
$(obj)/$(1).built-in.o: $(compel_std-$(1))
$(obj)/parasite-$(1).built-in.bin.o: $(obj)/$(1).built-in.o		\
				$(compel_pack_lds-$(1)) $(obj)/native.lib.a
	$$(call msg-gen, $$@)
	$(Q) $(LD) $(LD_R) -T $(compel_pack_lds-$(1)) -o $$@ $$< $(obj)/native.lib.a
endef

$(eval $(call map,gen-rule-built-in.bin.o,$(parasite_target)))

$(obj)/restorer.built-in.o: $(compel_std-native)
$(obj)/restorer.built-in.bin.o: $(obj)/restorer.built-in.o		\
				$(compel_pack_lds-native) $(obj)/native.lib.a
	$(call msg-gen, $@)
	$(Q) $(LD) $(LD_R) -T $(compel_pack_lds-native) -o $@ $< $(obj)/native.lib.a

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
cleanup-y += $(obj)/*.bin
cleanup-y += $(obj)/*.built-in.bin.o
cleanup-y += $(obj)/*.built-in.bin
