#ifndef __CR_LINKAGE_H__
#define __CR_LINKAGE_H__

#ifdef __ASSEMBLY__

#define __ALIGN		.align 4, 0x90
#define __ALIGN_STR	".align 4, 0x90"

#define GLOBAL(name)		\
	.globl name;		\
	name:

#define ENTRY(name)		\
	.globl name;		\
	.type name, @function;	\
	__ALIGN;		\
	name:

#define END(sym)		\
	.size sym, . - sym

#endif  /* __ASSEMBLY__ */

#define __USER32_CS	0x23
#define __USER_CS	0x33

#endif /* __CR_LINKAGE_H__ */
