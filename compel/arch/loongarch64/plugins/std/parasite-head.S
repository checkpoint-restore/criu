
#include "common/asm/linkage.h"

	.section .head.text, "ax"
ENTRY(__export_parasite_head_start)
	bl	parasite_service;
	break 0;
END(__export_parasite_head_start)

