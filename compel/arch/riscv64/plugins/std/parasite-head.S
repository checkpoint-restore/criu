#include "common/asm/linkage.h"

	.section .head.text, "ax"
ENTRY(__export_parasite_head_start)
	jal parasite_service
END(__export_parasite_head_start)