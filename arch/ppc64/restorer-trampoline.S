#include "asm/linkage.h"
#include "parasite.h"

	.section	.head.text
	.align		8

	// Called through parasite_unmap
	// This trampoline is there to restore r2 before jumping back to the
	// C code.
#define LOAD_REG_ADDR(reg, name)                \
        addis   reg,r7,(name - 0b)@ha;           \
        addi    reg,r7,(name - 0b)@l;

ENTRY(__export_unmap_trampoline)
        bl      0f
0:      mflr    r7
	LOAD_REG_ADDR(r8,restorer_r2)
	ld	r2,0(r8)
	b	__export_unmap
	//END(__export_restore_unmap_trampoline)

	// Called from JUMP_TO_RESTORER_BLOB, ctr contains the address where
	// to jump to, and r3 etc contains the parameter.
	// Assuming up to 4 parameters here since we are using r7 and r8.
ENTRY(__export_restore_task_trampoline)
        bl      0f
0:      mflr    r7
	LOAD_REG_ADDR(r8,restorer_r2)
	std	r2,0(r8)
	b	__export_restore_task

restorer_r2:
	.long	0
