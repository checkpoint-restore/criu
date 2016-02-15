#include "asm/linkage.h"

syscall_common:
	svc	#0
	ret


.macro syscall name, nr
	ENTRY(\name)
		mov	x8, \nr
		b	syscall_common
	END(\name)
.endm


ENTRY(__cr_restore_rt)
	mov	x8, __NR_rt_sigreturn
	svc	#0
END(__cr_restore_rt)
