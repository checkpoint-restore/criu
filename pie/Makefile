targets			+= parasite
targets			+= restorer

# used by obj-x to identify shared files built for parasite/restorer binaries
xsuffix			:= -pie-build

obj-y			+= log-simple.o
obj-x			+= util.o
obj-x			+= util-fd.o

ifeq ($(VDSO),y)
obj-x			+= util-vdso.o
obj-y			+= parasite-vdso.o
obj-e			+= $(ARCH_DIR)/vdso-pie.o
ifeq ($(SRCARCH),aarch64)
asm-e			+= $(ARCH_DIR)/intraprocedure.o
endif
ifeq ($(SRCARCH), ppc64)
asm-e			+= $(ARCH_DIR)/vdso-trampoline.o
endif
endif

ifeq ($(SRCARCH), ppc64)
asm-e			+= $(ARCH_DIR)/memcpy_power7.o
asm-e			+= $(ARCH_DIR)/memcmp_64.o
asm-e			+= $(ARCH_DIR)/misc.o
endif

parasite-obj-y		+= parasite.o
parasite-asm-e		+= $(ARCH_DIR)/parasite-head.o
parasite-libs-e		+= $(SYSCALL-LIB)

restorer-obj-y		+= restorer.o
restorer-obj-e		+= $(ARCH_DIR)/restorer.o
restorer-libs-e		+= $(SYSCALL-LIB)

#
# We can't provide proper mount implementation
# in parasite code -- it requires run-time rellocation
# applications, which is not the target of the
# project.
#
CFLAGS			:= $(filter-out -pg,$(CFLAGS)) -iquote pie/piegen

ifneq ($(filter-out i386 ia32, $(ARCH)),)
cflags-y		+= -DCR_NOGLIBC -fpie -Wa,--noexecstack -fno-stack-protector
else
cflags-y		+= -DCR_NOGLIBC -fno-pic -Wa,--noexecstack -fno-stack-protector
endif

ifeq ($(SRCARCH), arm)
	cflags-y	+= -marm
endif
ASMFLAGS		+= -D__ASSEMBLY__

GEN-OFFSETS		:= ../scripts/gen-offsets.sh
BLOBS			:= $(obj)/parasite-blob.h $(obj)/restorer-blob.h

PIELDS			:= pie.lds.S

.SECONDARY:

ifeq ($(piegen-y),y)
ldflags-y += -r
target-name = $(patsubst pie/%-blob.h,%,$(1))

ifeq ($(SRCARCH),ppc64)
$(obj)/$(PIELDS): $(obj)/pie-reloc.lds.S.in
	$(E) "  GEN     " $@
	$(Q) echo "OUTPUT_ARCH($(LDARCH))"              >  $(obj)/$(PIELDS)
	$(Q) cat $<					>> $(obj)/$(PIELDS)
else
ifeq ($(ARCH),x86_64)
$(obj)/$(PIELDS): $(obj)/pie-reloc.lds.S.in
	$(E) "  GEN     " $@
	$(Q) echo "OUTPUT_ARCH(i386:x86-64)"		>  $(obj)/$(PIELDS)
	$(Q) echo "TARGET(elf64-x86-64)"		>> $(obj)/$(PIELDS)
	$(Q) cat $<					>> $(obj)/$(PIELDS)
else # i386 ia32
$(obj)/$(PIELDS): $(obj)/pie-reloc.lds.S.in
	$(E) "  GEN     " $@
	$(Q) echo "OUTPUT_ARCH(i386)"			>  $(obj)/$(PIELDS)
	$(Q) echo "TARGET(elf32-i386)"			>> $(obj)/$(PIELDS)
	$(Q) cat $<					>> $(obj)/$(PIELDS)
endif
endif

ifeq ($(strip $(V)),)
piegen_stdout = >/dev/null
endif

$(obj)/%.built-in.bin.o: $(obj)/%.built-in.o $(obj)/$(PIELDS)
	$(E) "  GEN     " $@
	$(Q) $(LD) $(ldflags-y) -T $(obj)/$(PIELDS) -o $@ $<

$(obj)/%-blob.h: $(obj)/%.built-in.bin.o $(obj)/$(PIELDS) pie/piegen
	$(E) "  GEN     " $@
	$(Q) pie/piegen/piegen -f $< -v $(call target-name,$@)_relocs -p $(call target-name,$@)_blob_offset__ -s $(call target-name,$@)_blob -o $@ $(piegen_stdout)

else

$(obj)/$(PIELDS): $(obj)/$(PIELDS).in
	$(E) "  GEN     " $@
	$(Q) $(SH) -c "echo 'OUTPUT_ARCH($(LDARCH))'	 > $(obj)/$(PIELDS)"
	$(Q) $(SH) -c "cat $(obj)/$(PIELDS).in		>> $(obj)/$(PIELDS)"

$(obj)/%.built-in.bin.o: $(obj)/%.built-in.o $(obj)/$(PIELDS)
	$(E) "  GEN     " $@
	$(Q) $(LD) $(ldflags-y) -T $(obj)/$(PIELDS) -o $@ $<

$(obj)/%.built-in.bin: $(obj)/%.built-in.bin.o
	$(E) "  GEN     " $@
	$(Q) $(OBJCOPY) -O binary $^ $@

$(obj)/%-blob.h: $(obj)/%.built-in.bin $(obj)/$(GEN-OFFSETS)
	$(E) "  GEN     " $@
	$(Q) $(SH) $(obj)/$(GEN-OFFSETS) $(@:-blob.h=) $(notdir $(@:-blob.h=)) $(CROSS_COMPILE) > $@

endif

$(BLOBS): $(obj)/$(PIELDS)
_all += $(BLOBS)

cleanup-y += $(obj)/$(PIELDS)
cleanup-y += $(obj)/*.bin
cleanup-y += $(BLOBS)
cleanup-y += $(obj)/*.built-in.bin.o
cleanup-y += $(obj)/*.built-in.bin

ifneq ($(MAKECMDGOALS),clean)
incdeps := y
endif
