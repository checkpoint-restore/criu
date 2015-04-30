#include "asm/linkage.h"
#include "parasite.h"

	.section .head.text
	.align 8

ENTRY(__export_parasite_head_start)

	// int __used parasite_service(unsigned int cmd, void *args)
	// cmd  = r3 = *__export_parasite_cmd (u32 ?)
	// args = r4 = @parasite_args_ptr + @pc

	bl	0f
0:	mflr	2

#define LOAD_REG_ADDR(reg, name)		\
        addis   reg,2,(name - 0b)@ha;		\
        addi    reg,2,(name - 0b)@l;

	LOAD_REG_ADDR(3,__export_parasite_cmd)
	lwz	3,0(3)

	LOAD_REG_ADDR(4,parasite_args_ptr)
	lwz	4,0(4)
	add	4,4,2		// Fix up ptr

	// Set the TOC pointer
	LOAD_REG_ADDR(5,parasite_toc_ptr)
	ld	5,0(5)
	add	2,2,5		// Fix up ptr

	bl      parasite_service
	twi 	31,0,0		// Should generate SIGTRAP

parasite_args_ptr:
        .long __export_parasite_args - (0b - __export_parasite_head_start)

__export_parasite_cmd:
	.long 0

parasite_toc_ptr:
	.long .TOC. - (0b - __export_parasite_head_start)

END(__export_parasite_head_start)
