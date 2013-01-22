#include "asm/linkage.h"
#include "parasite.h"

	.section .head.text, "ax"
ENTRY(__export_parasite_head_start)
	adr	%sp, __export_parasite_stack
        adr     %r0, __export_parasite_cmd
	ldr	%r0, [%r0]
        adr     %r1, __export_parasite_args
	bl	parasite_service
        .byte   0xf0, 0x01, 0xf0, 0xe7          @ the instruction UDF #32 generates the signal SIGTRAP in Linux

__export_parasite_cmd:
	.long 0
__export_parasite_args:
	.long 0
	.space PARASITE_ARG_SIZE,0
	.space PARASITE_STACK_SIZE,0

        .space 228, 0

__export_parasite_stack:
	.long 0
END(__export_parasite_head_start)
