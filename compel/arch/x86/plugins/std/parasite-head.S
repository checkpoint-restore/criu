#include "common/asm/linkage.h"

	.section .head.text, "ax"

#ifndef CONFIG_X86_64
# error 64-bit parasite should compile with CONFIG_X86_64
#endif

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
