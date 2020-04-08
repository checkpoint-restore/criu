#include "common/asm/linkage.h"

#define SYSCALL(name, opcode)		\
	ENTRY(name);			\
	li v0, opcode;		\
	syscall;			\
	jr ra;				\
	nop;				\
	END(name)

ENTRY(__cr_restore_rt)
END(__cr_restore_rt)
