#include "common/asm/linkage.h"

	.section .head.text, "ax"
ENTRY(__export_parasite_head_start)
	adr	x2, __export_parasite_head_start	// get the address of this instruction

	ldr	x0, __export_parasite_cmd

	ldr	x1, parasite_args_ptr
	add	x1, x1, x2				// fixup __export_parasite_args

	bl	parasite_service
	brk	#0					// the instruction BRK #0 generates the signal SIGTRAP in Linux

parasite_args_ptr:
	.quad	__export_parasite_args

__export_parasite_cmd:
	.quad	0
END(__export_parasite_head_start)
