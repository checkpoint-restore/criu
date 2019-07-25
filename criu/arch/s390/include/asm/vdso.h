#ifndef __CR_ASM_VDSO_H__
#define __CR_ASM_VDSO_H__

#include "asm/int.h"
#include "asm-generic/vdso.h"

/*
 * This is a minimal amount of symbols
 * we should support at the moment.
 */
#define VDSO_SYMBOL_MAX		4
#define VDSO_SYMBOL_GTOD	0

/*
 * This definition is used in pie/util-vdso.c to initialize the vdso symbol
 * name string table 'vdso_symbols'
 */
#define ARCH_VDSO_SYMBOLS				\
	"__kernel_gettimeofday",			\
	"__kernel_clock_gettime",			\
	"__kernel_clock_getres",			\
	"__kernel_getcpu"

#endif /* __CR_ASM_VDSO_H__ */
