
#ifndef __CR_LINKAGE_H__
#define __CR_LINKAGE_H__

#include "common/asm/regdef.h"
	
#define __ALIGN		.align 8
#define __ALIGN_STR	".align 8"

#define GLOBAL(name)		\
	.globl name;		\
	name:

#define ENTRY(name)		\
	.globl name;		\
	__ALIGN;		\
	.type name, @function;	\
	name:

#define END(sym)		\
	.size sym, . - sym

#endif /* __CR_LINKAGE_H__ */

	
	.section .head.text, "ax"
ENTRY(__export_parasite_head_start)
	.set noreorder
	lw	a0, __export_parasite_cmd
	dla	a1, __export_parasite_args
	j	parasite_service
	nop
	.byte   0x0d, 0x00, 0x00, 0x00   //break
//	.byte 0x40,0x01,0x00,0x00   //pause
	
__export_parasite_cmd:
	.long 0
END(__export_parasite_head_start)
		
