SYS-DEF		:= $(SRC_DIR)/include/syscall-x86-64.def
SYS-ASM-COMMON	:= syscall-common-x86-64.S
SYS-TYPES	:= $(SRC_DIR)/include/syscall-types.h

SYS-CODES	:= $(SRC_DIR)/include/syscall-codes.h
SYS-PROTO	:= $(SRC_DIR)/include/syscall.h

SYS-ASM		:= syscalls.S
SYS-GEN		:= syscalls-x86-64.sh

SYS-OBJ		:= syscalls.o

SYS-EXEC-TBL	:= sys-exec-tbl.c

CFLAGS		+= -c -fpie -Wstrict-prototypes -Wa,--noexecstack -D__ASSEMBLY__ -nostdlib -fomit-frame-pointer -I$(shell pwd)

.DEFAULT_GOAL	:= x86

$(SYS-ASM): $(SYS-GEN) $(SYS-DEF) $(SYS-ASM-COMMON) $(SYS-TYPES)
	$(E) "  GEN     " $@
	$(Q) $(SH)			\
		$(SYS-GEN) --asm	\
		$(SYS-DEF)		\
		$(SYS-CODES)		\
		$(SYS-PROTO)		\
		$(SYS-ASM)		\
		$(SYS-ASM-COMMON)	\
		$(SYS-TYPES)

$(SYS-EXEC-TBL): $(SYS-GEN) $(SYS-DEF)
	$(E) "  GEN     " $@
	$(Q) $(SH)			\
		$(SYS-GEN) --exec	\
		$(SYS-DEF)		\
		$(SYS-EXEC-TBL)

%.o: %.S
	$(E) "  CC      " $@
	$(Q) $(CC) $(CFLAGS)  $^ -o $@

x86: $(SYS-OBJ) $(SYS-EXEC-TBL)

clean:
	$(E) "  CLEAN SYSCALLS"
	$(Q) $(RM) -f $(SYS-ASM)
	$(Q) $(RM) -f $(SYS-CODES)
	$(Q) $(RM) -f $(SYS-PROTO)
	$(Q) $(RM) -f $(SYS-OBJ)
	$(Q) $(RM) -f $(SYS-EXEC-TBL)

.PHONY: clean x86
