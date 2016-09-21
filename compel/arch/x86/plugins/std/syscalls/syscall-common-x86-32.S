#include "common/asm/linkage.h"

#define SYSCALL(name, opcode)		\
	ENTRY(name);			\
	movl	$opcode, %eax;		\
	jmp	__syscall_common;	\
	END(name)

ENTRY(__syscall_common)
	pushl	%ebx
	pushl	%esi
	pushl	%edi
	pushl	%ebp

#define __arg(n)	(4 * (n) + 20)(%esp)
	movl	__arg(0),%ebx
	movl	__arg(1),%ecx
	movl	__arg(2),%edx
	movl	__arg(3),%esi
	movl	__arg(4),%edi
	movl	__arg(5),%ebp
#undef __arg

	int	$0x80

	popl	%ebp
	popl	%edi
	popl	%esi
	popl	%ebx
	ret
END(__syscall_common)

ENTRY(__cr_restore_rt)
	movl	$__NR_rt_sigreturn, %eax
	jmp	__syscall_common
END(__cr_restore_rt)
