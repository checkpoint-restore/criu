#ifndef __CR_ASM_VDSO_H__
#define __CR_ASM_VDSO_H__

#include "asm/int.h"
#include "asm-generic/vdso.h"

/*
 * This is a minimal amount of symbols
 * we should support at the moment.
 */
#define VDSO_SYMBOL_MAX		4

#define ARCH_VDSO_SYMBOLS			\
	"__kernel_clock_getres",		\
	"__kernel_clock_gettime",		\
	"__kernel_gettimeofday",		\
	"__kernel_rt_sigreturn"

struct vdso_symtable;
extern int vdso_redirect_calls(unsigned long base_to,
			       unsigned long base_from,
			       struct vdso_symtable *to,
			       struct vdso_symtable *from);
extern void write_intraprocedure_branch(unsigned long to, unsigned long from);

#endif /* __CR_ASM_VDSO_H__ */
