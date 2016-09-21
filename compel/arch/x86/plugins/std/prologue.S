#include "common/asm/linkage.h"
#include "asm/prologue.h"

#include "uapi/std/syscall-codes.h"

	.section .compel.prologue.text, "ax"
ENTRY(__export_std_prologue_start)
	push	%rsp

	leaq	__export_std_prologue_init_args(%rip), %rdi
	movq	__export_std_plugin_begin(%rip), %rsi
	movq	__export_std_plugin_size(%rip), %rdx
	call	__export_std_compel_start

do_rt_sigreturn:
	leaq	__export_std_prologue_sigframe(%rip), %rax
	addq	$8, %rax
	movq	%rax, %rsp			# we can't use sys_rt_sigreturn here
	mov	$__NR_rt_sigreturn, %eax	# because we're adjusting stack
	syscall

GLOBAL(__export_std_prologue_init_args)
	.space PROLOGUE_INIT_ARGS_SIZE, 0

GLOBAL(__export_std_plugin_begin)
	.space 8, 0
GLOBAL(__export_std_plugin_size)
	.space 8, 0

	.align 64
GLOBAL(__export_std_prologue_sigframe)
	.space PROLOGUE_SGFRAME_SIZE, 0
END(__export_std_prologue_start)
