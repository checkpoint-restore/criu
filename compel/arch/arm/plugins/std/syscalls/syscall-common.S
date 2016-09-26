#include "common/asm/linkage.h"

@ We use the register R8 unlike libc that uses R12.
@ This avoids corruption of the register by the stub
@ for the syscall sys_munmap() when syscalls are hooked
@ by ptrace(). However we have to make sure that
@ the compiler doesn't use the register on the route
@ between parasite_service() and sys_munmap().

syscall_common:
	ldr	r7, [r7]
	add	r8, sp, #24
	ldm	r8, {r4, r5, r6}
	svc	0x00000000
	pop	{r4, r5, r6, r7, r8, pc}


.macro syscall name, nr
	.nr_\name :
		.long \nr

	ENTRY(\name)
		push	{r4, r5, r6, r7, r8, lr}
		adr		r7, .nr_\name
		b		syscall_common
	END(\name)
.endm


ENTRY(__cr_restore_rt)
	adr	r7, .nr_sys_rt_sigreturn
	ldr	r7, [r7]
	svc	#0
END(__cr_restore_rt)
