
#include "common/asm/linkage.h"
	
	
	.section .head.text, "ax"
ENTRY(__export_parasite_head_start)
	.set push
	.set noreorder
	lw	a0, __export_parasite_cmd
	dla	a1, __export_parasite_args
	jal	parasite_service
	nop
	.byte   0x0d, 0x00, 0x00, 0x00   //break
	.set pop
//	.byte 0x40,0x01,0x00,0x00   //pause
	
__export_parasite_cmd:
	.long 0
END(__export_parasite_head_start)
		
