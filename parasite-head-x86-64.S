#include "linkage.h"
#include "parasite.h"

	.section .head.text, "ax"
ENTRY(__export_parasite_head_start)
	leaq	__export_parasite_stack(%rip), %rsp
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
__export_parasite_args:
	.long 0
	.space PARASITE_ARG_SIZE,0
	.space PARASITE_STACK_SIZE,0
__export_parasite_stack:
	.long 0
END(__export_parasite_head_start)
