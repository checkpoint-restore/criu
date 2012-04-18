#ifndef LINKAGE_H_
#define LINKAGE_H_

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

#endif /* LINKAGE_H_ */
