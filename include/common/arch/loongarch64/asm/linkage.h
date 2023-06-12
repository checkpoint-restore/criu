#ifndef __CR_LINKAGE_H__
#define __CR_LINKAGE_H__

#define __ALIGN	    .align 2
#define __ALIGN_STR ".align 2"

#define GLOBAL(name) \
	.globl name; \
name:

#define ENTRY(name)            \
	.globl name;           \
	__ALIGN;               \
	.type name, @function; \
name:

#define END(sym) .size sym, .- sym

#endif /* __CR_LINKAGE_H__ */
