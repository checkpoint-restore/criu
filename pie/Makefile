targets			+= parasite
targets			+= restorer

obj-y			+= log-simple.o
obj-y			+= util.o
obj-y			+= util-fd.o

ifeq ($(VDSO),y)
obj-e			+= $(ARCH_DIR)/vdso-pie.o
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
CFLAGS			:= $(filter-out -pg,$(CFLAGS))

cflags-y		+= -DCR_NOGLIBC -fpie  -Wa,--noexecstack -fno-stack-protector
ifeq ($(SRCARCH), arm)
	cflags-y	+= -marm
endif
ASMFLAGS		+= -D__ASSEMBLY__

GEN-OFFSETS		:= ../scripts/gen-offsets.sh
BLOBS			:= $(obj)/parasite-blob.h $(obj)/restorer-blob.h

PIELDS			:= pie.lds.S

.SECONDARY:

$(obj)/$(PIELDS): $(obj)/$(PIELDS).in
	$(E) "  GEN     " $@
	$(Q) $(SH) -c "echo 'OUTPUT_ARCH($(LDARCH))'	 > $(obj)/$(PIELDS)"
	$(Q) $(SH) -c "cat $(obj)/$(PIELDS).in		>> $(obj)/$(PIELDS)"

$(obj)/%.built-in.bin.o: $(obj)/%.built-in.o $(obj)/$(PIELDS)
	$(E) "  GEN     " $@
	$(Q) $(LD) -T $(obj)/$(PIELDS) -o $@ $<

$(obj)/%.built-in.bin: $(obj)/%.built-in.bin.o
	$(E) "  GEN     " $@
	$(Q) $(OBJCOPY) -O binary $^ $@

$(obj)/%-blob.h: $(obj)/%.built-in.bin $(obj)/$(GEN-OFFSETS)
	$(E) "  GEN     " $@
	$(Q) $(SH) $(obj)/$(GEN-OFFSETS) $(@:-blob.h=) $(notdir $(@:-blob.h=)) $(CROSS_COMPILE) > $@

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
