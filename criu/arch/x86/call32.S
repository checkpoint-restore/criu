/*
 * call32.S - assembly helpers for mixed-bitness code
 * From kernel selftests originally: tools/testing/selftests/x86/thunks.S
 * Copyright (c) 2015 Andrew Lutomirski
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * These are little helpers that make it easier to switch bitness on
 * the fly.
 */

#include "common/asm/linkage.h"

	.text

/*
 * @rdi: Stack to use
 * @esi: Pointer to function for calling
 */
ENTRY(call32_from_64)
	/* Callee-saving registers due to ABI */
	pushq %rbx
	pushq %rbp
	pushq %r12
	pushq %r13
	pushq %r14
	pushq %r15
	pushfq

	/* Switch stacks */
	sub $8, %rdi
	mov %rsp,(%rdi)
	mov %rdi,%rsp

	/* Push return address and 64-bit segment descriptor */
	sub $4, %rsp
	movl $__USER_CS,(%rsp)
	sub $4, %rsp
	/* Using rip-relative addressing to get rid of R_X86_64_32S relocs */
	leaq 2f(%rip),%r12
	movl %r12d,(%rsp)

	/* Switch into compatibility mode */
	pushq $__USER32_CS
	/* Using rip-relative addressing to get rid of R_X86_64_32S relocs */
	leaq 1f(%rip), %r12
	pushq %r12
	lretq

1:	.code32
	/* Run function and switch back */
	call *%esi
	lret

2:	.code64
	/* Restore the stack */
	mov (%rsp),%rsp
	add $8, %rdi

	/* Restore registers */
	popfq
	popq %r15
	popq %r14
	popq %r13
	popq %r12
	popq %rbp
	popq %rbx
	ret
END(call32_from_64)
