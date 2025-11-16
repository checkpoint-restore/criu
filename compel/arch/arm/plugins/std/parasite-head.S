#include "common/asm/linkage.h"

	.section .head.text, "ax"
ENTRY(__export_parasite_head_start)
	bl	parasite_service
	.byte   0xf0, 0x01, 0xf0, 0xe7		@ the instruction UDF #32 generates the signal SIGTRAP in Linux

END(__export_parasite_head_start)
