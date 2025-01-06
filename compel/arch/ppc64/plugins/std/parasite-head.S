#include "common/asm/linkage.h"

	.section .head.text
	.align 8

ENTRY(__export_parasite_head_start)
	bl	0f
0:	mflr	r2

#define LOAD_REG_ADDR(reg, name)		\
        addis   reg,r2,(name - 0b)@ha;		\
        addi    reg,r2,(name - 0b)@l;

	LOAD_REG_ADDR(r12,parasite_service_ptr)
	ld	r12,0(r12)
	mtctr	r12

	bctrl			// call parasite_service
	twi 	31,0,0		// Should generate SIGTRAP

parasite_service_ptr:
	// We want to run the function prototype to set r2.
	// Since the relocation will prefer the local entry
	// point, we force it to the global one which is 2
	// instructions above the local one.
	// FIXME: There should be a way to specify the global entry here.
	.quad	parasite_service - 8

END(__export_parasite_head_start)
