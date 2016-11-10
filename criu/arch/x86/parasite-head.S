#include "common/asm/linkage.h"
#include "parasite.h"

	.section .head.text, "ax"

#ifdef CONFIG_X86_64

ENTRY(__export_parasite_head_start)
	subq	$16, %rsp
	andq	$~15, %rsp
	pushq	$0
	movq	%rsp, %rbp
	movl	__export_parasite_cmd(%rip), %edi
	leaq	__export_parasite_args(%rip), %rsi
	call	parasite_service
	int	$0x03
	.align 8
__export_parasite_cmd:
	.long 0
END(__export_parasite_head_start)

#else /* CONFIG_X86_64 */

ENTRY(__export_parasite_head_start)
	subl	$16, %esp
	andl	$~15, %esp
	pushl	$0
	movl	%esp, %ebp
	call	1f
1:	popl	%ecx
2:	leal	(__export_parasite_cmd-2b)(%ecx), %eax
	leal	(__export_parasite_args-2b)(%ecx), %edx
	call	parasite_service
	int	$0x03
	.align 8
GLOBAL(__export_parasite_cmd)
	.long 0
END(__export_parasite_head_start)

#endif /* CONFIG_X86_64 */
