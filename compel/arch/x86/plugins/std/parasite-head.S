#include "common/asm/linkage.h"

	.section .head.text, "ax"

#ifndef CONFIG_X86_64
# error 64-bit parasite should compile with CONFIG_X86_64
#endif

.macro PARASITE_ENTRY num
	subq	$16, %rsp
	andq	$~15, %rsp
	pushq	$\num
	movq	%rsp, %rbp
	movl	__export_parasite_cmd(%rip), %edi
	leaq	__export_parasite_args(%rip), %rsi
	call	parasite_service
.endm

#ifdef CONFIG_COMPAT
.code32
ENTRY(__export_parasite_head_start_compat)
	/* A long jump to 64-bit parasite. */
	jmp	$__USER_CS,$1f
1:
.code64
	PARASITE_ENTRY 0
	pushq	$__USER32_CS
	xor	%r11, %r11
	movl	$2f, %r11d
	pushq   %r11
	lretq
2:
.code32
	/*
	 * parasite_service() can run commands in non-daemon mode
	 * with parasite_trap_cmd(): it waits that after return there
	 * is a software break.
	 * compel_run_in_thread() uses this and after hitting the break,
	 * it restores register set - that's the reason, why we should
	 * stop in 32-bit mode for compat tasks here.
	 */
	int	$0x03
END(__export_parasite_head_start_compat)
.code64
#endif

ENTRY(__export_parasite_head_start)
	PARASITE_ENTRY 0
	int	$0x03
END(__export_parasite_head_start)

.align 8
GLOBAL(__export_parasite_cmd)
	.long 0
