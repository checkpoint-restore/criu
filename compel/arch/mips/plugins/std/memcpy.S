
#include "common/asm/linkage.h"
	
	.section .head.text, "ax"
ENTRY(memcpy)
	.set noreorder
	dadd v0,zero,a0
	daddiu t1,zero,0
loop:	
	beq t1,a2,exit
	nop
	lb t2,0(a1)
	sb t2,0(a0)
	daddiu t1,t1,1
	daddiu a0,a0,1
	daddiu a1,a1,1
	j loop
	nop
exit:
	jr ra
	nop
END(memcpy)
		
