targets		+= syscalls
targets		+= crtools

SYS-ASM		:= syscalls.S

syscalls-asm-y	+= $(SYS-ASM:.S=).o
crtools-obj-y	+= crtools.o
crtools-obj-y	+= cpu.o

SYS-DEF		:= syscall-ppc64.def
SYS-ASM-COMMON	:= syscall-common-ppc64.S

SYS-TYPES	:= include/syscall-types.h
SYS-CODES	:= include/syscall-codes.h
SYS-PROTO	:= include/syscall.h

SYS-GEN		:= syscalls-ppc64.sh

SYS-EXEC-TBL	:= sys-exec-tbl.c

syscalls-asm-y-asmflags	:= -fpie -Wstrict-prototypes -Wa,--noexecstack
syscalls-asm-y-asmflags += -nostdlib -fomit-frame-pointer -I$(obj)

ASMFLAGS	+= -D__ASSEMBLY__

$(obj)/$(SYS-ASM): $(obj)/$(SYS-GEN) $(obj)/$(SYS-DEF) $(obj)/$(SYS-ASM-COMMON) $(SYS-TYPES)
	$(E) "  GEN     " $@
	$(Q) $(SH)				\
		$(obj)/$(SYS-GEN) --asm		\
		$(obj)/$(SYS-DEF)		\
		$(SYS-CODES)			\
		$(SYS-PROTO)			\
		$(obj)/$(SYS-ASM)		\
		$(SYS-ASM-COMMON)		\
		$(SYS-TYPES)

$(obj)/syscalls.o: $(obj)/$(SYS-ASM)

$(obj)/$(SYS-EXEC-TBL): $(obj)/$(SYS-GEN) $(obj)/$(SYS-DEF)
	$(E) "  GEN     " $@
	$(Q) $(SH)				\
		$(obj)/$(SYS-GEN) --exec	\
		$(obj)/$(SYS-DEF)		\
		$(obj)/$(SYS-EXEC-TBL)

_all += $(obj)/$(SYS-EXEC-TBL)

cleanup-y += $(obj)/$(SYS-EXEC-TBL) $(obj)/$(SYS-ASM)
cleanup-y += $(SYS-CODES)
cleanup-y += $(SYS-PROTO)

ifneq ($(MAKECMDGOALS),clean)
deps-after := $(obj)/$(SYS-ASM)
incdeps := y
endif
