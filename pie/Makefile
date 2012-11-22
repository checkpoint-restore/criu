CFLAGS		+= -c -I$(SRC_DIR)/protobuf/ -I$(SRC_DIR)/syscall/
CFLAGS		+=  -fpie  -Wa,--noexecstack -fno-strict-aliasing

GEN-OFFSETS	:= gen-offsets.sh

PASM-OBJS	+= parasite-head-x86-64.o

PARASITE	+= parasite.bin.o parasite.bin
RESTORER	:= restorer.bin.o restorer.bin
BLOBS		:= parasite-blob.h restorer-blob.h
PIELDS		:= pie.lds.S
ASMFLAGS	:= -D__ASSEMBLY__

.DEFAULT_GOAL	:= pie

LIB-OBJS	= log-simple.o blob-util-net.o $(SYSCALL-LIB)

$(PARASITE): $(LIB-OBJS) $(PASM-OBJS) $(PIELDS)
$(RESTORER): $(LIB-OBJS) $(PIELDS)

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
	$(Q) $(LD) --oformat=elf64-x86-64 -T $(PIELDS) -o $@ $(^:$(PIELDS)=)

%.bin: %.o
	$(E) "  GEN     " $@
	$(Q) $(LD) --oformat=binary -T $(PIELDS) -o $@ $(^:$(PIELDS)=)

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

.PHONY: clean pie
.SECONDARY:
