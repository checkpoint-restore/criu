#include "asm/linkage.h"

syscall_common:
	ldr	%r7, [%r7]
	add	%ip, %sp, #16
	ldm	%ip, {%r4, %r5, %r6}
	svc	0x00000000
	pop	{%r4, %r5, %r6, %r7}
	bx	%lr


.macro syscall name, nr
	.nr_\name :
		.long \nr

	ENTRY(\name)
		push	{%r4, %r5, %r6, %r7}
		adr		%r7, .nr_\name
		b		syscall_common
	END(\name)
.endm


ENTRY(__cr_restore_rt)
	adr	%r7, .nr_sys_rt_sigreturn
	ldr	%r7, [%r7]
	svc	#0
END(__cr_restore_rt)
