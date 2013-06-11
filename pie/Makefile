targets			+= parasite
targets 		+= restorer

obj-y			+= log-simple.o
obj-y			+= util-net.o

parasite-obj-y		+= parasite.o
parasite-asm-e		+= $(ARCH_DIR)/parasite-head.o
parasite-libs-e		+= $(SYSCALL-LIB)

restorer-obj-y		+= restorer.o
restorer-obj-e		+= $(ARCH_DIR)/restorer.o
restorer-obj-e		+= $(ARCH_DIR)/vdso-pie.o
restorer-libs-e		+= $(SYSCALL-LIB)

cflags-y		+= -DCR_NOGLIBC -fpie  -Wa,--noexecstack -fno-stack-protector
ifeq ($(ARCH), arm)
	cflags-y	+= -marm
endif
ASMFLAGS		+= -D__ASSEMBLY__

GEN-OFFSETS		:= gen-offsets.sh
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

ifneq ($(MAKECMDGOALS),clean)
incdeps := y
endif
