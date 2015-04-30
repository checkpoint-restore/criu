#ifndef __CR_LINKAGE_H__
#define __CR_LINKAGE_H__

#ifdef __ASSEMBLY__

#define GLOBAL(name)		\
	.globl name;		\
	name:

#define ENTRY(name)		\
	.globl name;		\
	.type name, @function;	\
	name:

#define END(sym)		\
	.size sym, . - sym

#endif  /* __ASSEMBLY__ */

#endif /* __CR_LINKAGE_H__ */
