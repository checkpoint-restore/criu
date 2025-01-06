#ifndef __ASM_LINKAGE_H
#define __ASM_LINKAGE_H

#ifdef __ASSEMBLY__

#define __ALIGN .align 4, 0x07

#define GLOBAL(name) \
	.globl name; \
	name:

#define ENTRY(name)            \
	.globl name;           \
	.type name, @function; \
	__ALIGN;               \
	name:

#define END(name) .size name, .- name

#endif /* __ASSEMBLY__ */
#endif
