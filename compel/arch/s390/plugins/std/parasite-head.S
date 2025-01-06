#include "common/asm/linkage.h"

	.section .head.text, "ax"

ENTRY(__export_parasite_head_start)
	brasl	%r14,parasite_service
	.long 0x00010001	/* S390_BREAKPOINT_U16: Generates SIGTRAP */
END(__export_parasite_head_start)
