target			+= parasite
target			+= restorer

parasite-obj-y		+= parasite.o

restorer-obj-y		+= restorer.o
restorer-obj-y		+= ./$(ARCH_DIR)/restorer.o

ifeq ($(ARCH),x86)
# FIXME: depend on 32/64 pie type
parasite-obj-y		+= ./$(ARCH_DIR)/parasite-head-64.o
parasite-obj-e		+= ./$(ARCH_DIR)/syscalls-64.built-in.o
restorer-obj-e		+= ./$(ARCH_DIR)/syscalls-64.built-in.o
else
parasite-obj-y		+= ./$(ARCH_DIR)/parasite-head.o
parasite-obj-e		+= ./$(ARCH_DIR)/syscalls.built-in.o
restorer-obj-e		+= ./$(ARCH_DIR)/syscalls.built-in.o
endif

#
# We can't provide proper mount implementation
# in parasite code -- it requires run-time rellocation
# applications, which is not the target of the
# project.
#
CFLAGS			:= $(filter-out -pg $(CFLAGS-GCOV),$(CFLAGS))
CFLAGS			+= -iquote $(SRC_DIR)/compel/include
CFLAGS			+= -iquote $(SRC_DIR)/criu/arch/$(ARCH)/include
CFLAGS			+= -iquote $(SRC_DIR)/criu/include
CFLAGS			+= -iquote $(SRC_DIR)/include
CFLAGS			+= -iquote $(SRC_DIR)
CFLAGS			+= -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0
CFLAGS			+= -Wp,-U_FORTIFY_SOURCE -Wp,-D_FORTIFY_SOURCE=0


ccflags-y		+= -DCR_NOGLIBC
ifneq ($(filter-out clean mrproper,$(MAKECMDGOALS)),)
	ccflags-y	+= $(shell $(SRC_DIR)/compel/compel --arch=$(ARCH) cflags)
endif

ifeq ($(SRCARCH),arm)
        ccflags-y	+= -marm
endif

asflags-y		+= -D__ASSEMBLY__

GEN-OFFSETS		:= $(obj)/../../scripts/gen-offsets.sh
BLOBS			:= $(obj)/parasite-blob.h $(obj)/restorer-blob.h

PIELDS			:= pie.lds.S

.SECONDARY:

ifeq ($(piegen-y),y)
target-name = $(patsubst criu/pie/%-blob.h,%,$(1))

ifeq ($(SRCARCH),ppc64)
$(obj)/$(PIELDS): $(obj)/pie-reloc.lds.S.in
	$(call msg-gen, $@)
	$(Q) echo "OUTPUT_ARCH($(LDARCH))"              >  $(obj)/$(PIELDS)
	$(Q) cat $<					>> $(obj)/$(PIELDS)
else
ifeq ($(ARCH),x86)
$(obj)/$(PIELDS): $(obj)/pie-reloc.lds.S.in
	$(call msg-gen, $@)
	$(Q) echo "OUTPUT_ARCH(i386:x86-64)"		>  $(obj)/$(PIELDS)
	$(Q) echo "TARGET(elf64-x86-64)"		>> $(obj)/$(PIELDS)
	$(Q) cat $<					>> $(obj)/$(PIELDS)
else # i386 ia32
$(obj)/$(PIELDS): $(obj)/pie-reloc.lds.S.in
	$(call msg-gen, $@)
	$(Q) echo "OUTPUT_ARCH(i386)"			>  $(obj)/$(PIELDS)
	$(Q) echo "TARGET(elf32-i386)"			>> $(obj)/$(PIELDS)
	$(Q) cat $<					>> $(obj)/$(PIELDS)
endif
endif

ifeq ($(strip $(V)),)
        piegen_stdout := >/dev/null
endif

$(obj)/%.built-in.bin.o: $(obj)/%.built-in.o $(obj)/native.lib.a $(obj)/$(PIELDS)
	$(call msg-gen, $@)
	$(Q) $(LD) -r -T $(obj)/$(PIELDS) -o $@ $< $(obj)/native.lib.a

$(obj)/%-blob.h: $(obj)/%.built-in.bin.o $(obj)/$(PIELDS) compel/compel
	$(call msg-gen, $@)
	$(Q) compel/compel piegen -f $< -v $(call target-name,$@)_relocs -p $(call target-name,$@)_blob_offset__ -s $(call target-name,$@)_blob -o $@ $(piegen_stdout)

else

$(obj)/$(PIELDS): $(obj)/$(PIELDS).in
	$(call msg-gen, $@)
	$(Q) $(SH) -c "echo 'OUTPUT_ARCH($(LDARCH))'	 > $(obj)/$(PIELDS)"
	$(Q) $(SH) -c "cat $(obj)/$(PIELDS).in		>> $(obj)/$(PIELDS)"

# ld on arm doesn't like -pie and -r options together
ifeq ($(filter arm aarch64,$(ARCH)),)
        LD_R := -r
endif

$(obj)/%.built-in.bin.o: $(obj)/%.built-in.o $(obj)/$(PIELDS) $(obj)/lib.a
	$(call msg-gen, $@)
	$(Q) $(LD) $(LD_R) -T $(obj)/$(PIELDS) -o $@ $< $(obj)/lib.a

$(obj)/%.built-in.bin: $(obj)/%.built-in.bin.o
	$(call msg-gen, $@)
	$(Q) $(OBJCOPY) -O binary $^ $@

$(obj)/%-blob.h: $(obj)/%.built-in.bin $(GEN-OFFSETS)
	$(call msg-gen, $@)
	$(Q) $(SH) $(GEN-OFFSETS) $(@:-blob.h=) $(notdir $(@:-blob.h=)) $(CROSS_COMPILE) > $@

endif

$(BLOBS): $(obj)/$(PIELDS)
all-y += $(BLOBS)

# blobs and pields are in cleanup, rather than in mrproper because
# we want them to be re-generated after `make clean && make`
cleanup-y += $(BLOBS)
cleanup-y += $(obj)/$(PIELDS)
cleanup-y += $(obj)/*.bin
cleanup-y += $(obj)/*.built-in.bin.o
cleanup-y += $(obj)/*.built-in.bin
