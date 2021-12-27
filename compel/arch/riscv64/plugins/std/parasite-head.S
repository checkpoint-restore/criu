#include "common/asm/linkage.h"

	.section .head.text, "ax"
ENTRY(__export_parasite_head_start)
	bl	parasite_service
	brk	#0					// the instruction BRK #0 generates the signal SIGTRAP in Linux
END(__export_parasite_head_start)
