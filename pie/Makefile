CFLAGS		+= -c -I$(SRC_DIR)/protobuf/ -I$(SRC_DIR)/syscall/
CFLAGS		+=  -fpie  -Wa,--noexecstack -fno-strict-aliasing

GEN-OFFSETS	:= gen-offsets.sh

PASM-OBJS	+= $(ARCH_DIR)/parasite-head.o

PARASITE	+= parasite.bin.o parasite.bin
RESTORER	:= restorer.bin.o restorer.bin
BLOBS		:= parasite-blob.h restorer-blob.h
PIELDS		:= pie.lds.S
ASMFLAGS	:= -D__ASSEMBLY__

.DEFAULT_GOAL	:= pie

LIB-OBJS	= log-simple.o blob-util-net.o $(SYSCALL-LIB)

$(PARASITE): $(LIB-OBJS) $(PASM-OBJS) $(PIELDS)
$(RESTORER): $(LIB-OBJS) $(PIELDS)

$(PIELDS): $(PIELDS).in
	$(E) "  GEN     " $@
	$(Q) $(SH) -c "echo 'OUTPUT_ARCH($(LDARCH))' > $(PIELDS)"
	$(Q) $(SH) -c "cat $(PIELDS).in >> $(PIELDS)"

blob-util-net.o: $(SRC_DIR)/util-net.c
	$(E) "  CC      " $@
	$(Q) $(CC) $(CFLAGS) $< -o $@

%.o: %.S
	$(E) "  CC      " $@
	$(Q) $(CC) $(ASMFLAGS) $(CFLAGS) $< -o $@

%.o: %.c
	$(E) "  CC      " $@
	$(Q) $(CC) $(CFLAGS) $< -o $@

%.bin.o: %.o
	$(E) "  GEN     " $@
	$(Q) $(LD) -T $(PIELDS) -o $@ $(^:$(PIELDS)=)

%.bin: %.bin.o
	$(E) "  GEN     " $@
	$(Q) $(OBJCOPY) -O binary $< $@

%-blob.h: %.bin %.bin.o $(GEN-OFFSETS)
	$(E) "  GEN     " $@
	$(Q) $(SH) $(GEN-OFFSETS) $(@:-blob.h=) > $@ || rm -f $@

pie: $(BLOBS)

clean:
	$(E) "  CLEAN PIE"
	$(Q) $(RM) -f ./*-blob.h
	$(Q) $(RM) -f ./*.o
	$(Q) $(RM) -f ./*.d
	$(Q) $(RM) -f ./*.bin
	$(Q) $(RM) -f ./*.bin.o
	$(Q) $(RM) -f $(PIELDS)

.PHONY: clean pie
.SECONDARY:
