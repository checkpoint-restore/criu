#ifndef __CR_ASM_VDSO_H__
#define __CR_ASM_VDSO_H__

#include "asm/int.h"
#include "asm-generic/vdso.h"

/* This definition is used in pie/util-vdso.c to initialize the vdso symbol
 * name string table 'vdso_symbols'
 */

/*
 * This is a minimal amount of symbols
 * we should support at the moment.
 */
#define VDSO_SYMBOL_MAX	7

#define ARCH_VDSO_SYMBOLS			\
	"__vdso_clock_gettime",			\
	"__vdso_getcpu",			\
	"__vdso_gettimeofday",			\
	"__vdso_time",				\
	"__kernel_vsyscall",			\
	"__kernel_sigreturn",			\
	"__kernel_rt_sigreturn"


#endif /* __CR_ASM_VDSO_H__ */
