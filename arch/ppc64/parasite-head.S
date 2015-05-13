#include "asm/linkage.h"
#include "parasite.h"

	.section .head.text
	.align 8

ENTRY(__export_parasite_head_start)

	// int __used parasite_service(unsigned int cmd, void *args)
	// cmd  = r3 = *__export_parasite_cmd (u32 ?)
	// args = r4 = @parasite_args_ptr + @pc

	bl	0f
0:	mflr	r2

#define LOAD_REG_ADDR(reg, name)		\
        addis   reg,r2,(name - 0b)@ha;		\
        addi    reg,r2,(name - 0b)@l;

	LOAD_REG_ADDR(r3,__export_parasite_cmd)
	lwz	r3,0(r3)

	LOAD_REG_ADDR(r4,parasite_args_ptr)
	lwz	r4,0(r4)
	add	r4,r4,r2	// Fix up ptr

	// Set the TOC pointer
	LOAD_REG_ADDR(r5,parasite_toc_ptr)
	ld	r5,0(r5)
	add	r2,r2,r5	// Fix up ptr

	bl      parasite_service
	twi 	31,0,0		// Should generate SIGTRAP

parasite_args_ptr:
        .long __export_parasite_args - (0b - __export_parasite_head_start)

__export_parasite_cmd:
	.long 0

parasite_toc_ptr:
	.long .TOC. - (0b - __export_parasite_head_start)

END(__export_parasite_head_start)
