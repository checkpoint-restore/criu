#include "common/asm/linkage.h"
#include "parasite.h"

	.section .head.text, "ax"

#ifndef CONFIG_X86_32
# error 32-bit parasite should compile with CONFIG_X86_32
#endif

ENTRY(__export_parasite_head_start)
	subl	$16, %esp
	andl	$~15, %esp
	pushl	$0
	movl	%esp, %ebp
	call	1f
1:	popl	%ecx
	movl	(__export_parasite_cmd-1b)(%ecx), %eax
	leal	(__export_parasite_args-1b)(%ecx), %edx
	call	parasite_service
	int	$0x03
	.align 8
GLOBAL(__export_parasite_cmd)
	.long 0
END(__export_parasite_head_start)
