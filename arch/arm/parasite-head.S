#include "asm/linkage.h"
#include "parasite.h"

	.section .head.text, "ax"
ENTRY(__export_parasite_head_start)
	sub	%r2, %pc, #8			@ get the address of this instruction

	adr	%sp, parasite_stack_ptr
	ldr	%sp, [%sp]
	add	%sp, %sp, %r2			@ fixup __export_parasite_stack
	bic	%sp, %sp, #7			@ align the stack

        adr     %r0, __export_parasite_cmd
	ldr	%r0, [%r0]

        adr     %r1, parasite_args_ptr
	ldr	%r1, [%r1]
	add	%r1, %r1, %r2			@ fixup __export_parasite_args

	bl	parasite_service
        .byte   0xf0, 0x01, 0xf0, 0xe7          @ the instruction UDF #32 generates the signal SIGTRAP in Linux

parasite_args_ptr:
	.long __export_parasite_args

parasite_stack_ptr:
	.long __export_parasite_stack

__export_parasite_cmd:
	.long 0
	.space PARASITE_STACK_SIZE,0

.align 3
__export_parasite_stack:
	.long 0
END(__export_parasite_head_start)
