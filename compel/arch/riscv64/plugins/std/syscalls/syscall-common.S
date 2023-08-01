#include "common/asm/linkage.h"

syscall_common:
	ecall
	ret

.macro syscall name, nr
	ENTRY(\name)
		li	a7, \nr
		j	syscall_common
	END(\name)
.endm

ENTRY(__cr_restore_rt)
	li	a7, __NR_rt_sigreturn
	ecall
END(__cr_restore_rt)