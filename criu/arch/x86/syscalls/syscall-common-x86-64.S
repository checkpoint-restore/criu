#include "asm/linkage.h"

#define SYSCALL(name, opcode)		\
	ENTRY(name);			\
	movl	$opcode, %eax;		\
	jmp	__syscall_common;	\
	END(name)

	.text
	.align	4

ENTRY(__syscall_common)
	movq	%rcx, %r10
	syscall
	ret
END(__syscall_common)

ENTRY(__cr_restore_rt)
	movq $__NR_rt_sigreturn, %rax
	syscall
END(__cr_restore_rt)
