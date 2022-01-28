#include "common/asm/linkage.h"

syscall_common:
	scause	#1
	sret


.macro syscall name, nr
	ENTRY(\name)
		addi	x8, x0, \nr
		j	syscall_common
	END(\name)
.endm


ENTRY(__cr_restore_rt)
	addi	x8, x0,	__NR_rt_sigreturn
	scause	#1
END(__cr_restore_rt)
