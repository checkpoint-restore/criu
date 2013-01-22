SYS-DEF		:= $(ARCH_DIR)/syscall.def
SYS-ASM-COMMON	:= syscall-common.S
SYS-TYPES	:= $(SRC_DIR)/include/syscall-types.h

SYS-CODES	:= $(SRC_DIR)/include/syscall-codes.h
SYS-PROTO	:= $(SRC_DIR)/include/syscall.h

SYS-ASM		:= syscalls.S
SYS-GEN		:= $(ARCH_DIR)/gen-syscalls.pl
SYS-GEN-TBL	:= $(ARCH_DIR)/gen-sys-exec-tbl.pl

SYS-OBJ		:= syscalls.o

SYS-EXEC-TBL	:= sys-exec-tbl.c

CFLAGS		+= -c -fpie -Wstrict-prototypes -Wa,--noexecstack -D__ASSEMBLY__ -nostdlib -fomit-frame-pointer -I$(shell pwd)

ARCH_BITS	:= 32

.DEFAULT_GOAL	:= arm

$(SYS-ASM): $(SYS-GEN) $(SYS-DEF) $(SYS-ASM-COMMON) $(SYS-TYPES)
	$(E) "  GEN     " $@
	$(Q) perl			\
		$(SYS-GEN)		\
		$(SYS-DEF)		\
		$(SYS-CODES)		\
		$(SYS-PROTO)		\
		$(SYS-ASM)		\
		$(SYS-ASM-COMMON)	\
		$(SYS-TYPES)		\
		$(ARCH_BITS)

$(SYS-EXEC-TBL): $(SYS-GEN-TBL) $(SYS-DEF)
	$(E) "  GEN     " $@
	$(Q) perl			\
		$(SYS-GEN-TBL)		\
		$(SYS-DEF)		\
		$(SYS-EXEC-TBL)		\
		$(ARCH_BITS)

%.o: %.S
	$(E) "  CC      " $@
	$(Q) $(CC) $(CFLAGS)  $^ -o $@

arm: $(SYS-OBJ) $(SYS-EXEC-TBL)

clean:
	$(E) "  CLEAN SYSCALLS"
	$(Q) $(RM) -f $(SYS-ASM)
	$(Q) $(RM) -f $(SYS-CODES)
	$(Q) $(RM) -f $(SYS-PROTO)
	$(Q) $(RM) -f $(SYS-OBJ)
	$(Q) $(RM) -f $(SYS-EXEC-TBL)
	$(Q) $(RM) -f *.o *.d

.PHONY: clean arm
