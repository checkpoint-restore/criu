#include "common/asm/linkage.h"

syscall_common:
	scause	#1
	sret


.macro syscall name, nr
	ENTRY(\name)
		mv	x8, \nr
		b	syscall_common
	END(\name)
.endm


ENTRY(__cr_restore_rt)
	mv	x8, __NR_rt_sigreturn
	scause	#1
END(__cr_restore_rt)
