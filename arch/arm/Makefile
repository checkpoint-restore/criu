targets		+= syscalls
targets		+= crtools

SYS-ASM		:= syscalls.S

syscalls-asm-y	+= $(SYS-ASM:.S=).o
crtools-obj-y	+= crtools.o
crtools-obj-y	+= cpu.o

SYS-DEF		:= syscall.def
SYS-ASM-COMMON	:= syscall-common.S
SYS-TYPES	:= include/syscall-types.h

SYS-CODES	:= include/syscall-codes.h
SYS-PROTO	:= include/syscall.h

SYS-GEN		:= ../scripts/arm/gen-syscalls.pl
SYS-GEN-TBL	:= ../scripts/arm/gen-sys-exec-tbl.pl

SYS-EXEC-TBL	:= sys-exec-tbl.c

syscalls-asm-y-asmflags		+= -fpie -Wstrict-prototypes -Wa,--noexecstack
syscalls-asm-y-asmflags		+= -nostdlib -fomit-frame-pointer -I$(obj)
ASMFLAGS	+= -D__ASSEMBLY__

ARCH_BITS	:= 32

$(obj)/$(SYS-ASM): $(obj)/$(SYS-GEN) $(obj)/$(SYS-DEF) $(obj)/$(SYS-ASM-COMMON) $(SYS-TYPES)
	$(E) "  GEN     " $@
	$(Q) perl			\
		$(obj)/$(SYS-GEN)	\
		$(obj)/$(SYS-DEF)	\
		$(SYS-CODES)		\
		$(SYS-PROTO)		\
		$(obj)/$(SYS-ASM)	\
		$(SYS-ASM-COMMON)	\
		$(SYS-TYPES)		\
		$(ARCH_BITS)

$(obj)/syscalls.o: $(obj)/$(SYS-ASM)

$(obj)/$(SYS-EXEC-TBL): $(obj)/$(SYS-GEN-TBL) $(obj)/$(SYS-DEF)
	$(E) "  GEN     " $@
	$(Q) perl			\
		$(obj)/$(SYS-GEN-TBL)	\
		$(obj)/$(SYS-DEF)	\
		$(obj)/$(SYS-EXEC-TBL)	\
		$(ARCH_BITS)

_all += $(obj)/$(SYS-EXEC-TBL)

cleanup-y += $(obj)/$(SYS-EXEC-TBL) $(obj)/$(SYS-ASM)
cleanup-y += $(SYS-CODES)
cleanup-y += $(SYS-PROTO)

ifneq ($(MAKECMDGOALS),clean)
deps-after := $(obj)/$(SYS-ASM)
incdeps := y
endif
