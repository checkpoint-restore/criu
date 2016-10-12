#include "asm/linkage.h"

/* The following code is taken from Linux kernel (arch/x86/lib/memcpy_64.S).
 * There are 3 implementations in there, we use the one that relies on
 * X86_FEATURE_REP_GOOD ("rep microcode works well").
 */

/*
 * memcpy - Copy a memory block.
 *
 * Input:
 *  rdi destination
 *  rsi source
 *  rdx count
 *
 * Output:
 * rax original destination
 */
ENTRY(memcpy_x86)
ENTRY(memcpy)
	movq %rdi, %rax
	movq %rdx, %rcx
	shrq $3, %rcx
	andl $7, %edx
	rep movsq
	movl %edx, %ecx
	rep movsb
	ret
END(memcpy)
END(memcpy_x86)
