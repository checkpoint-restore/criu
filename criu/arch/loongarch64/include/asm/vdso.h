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
#define VDSO_SYMBOL_MAX	 5
#define VDSO_SYMBOL_GTOD 3

#define ARCH_VDSO_SYMBOLS_LIST                                   \
	const char *aarch_vdso_symbol1 = "__vdso_getcpu";        \
	const char *aarch_vdso_symbol2 = "__vdso_clock_getres";  \
	const char *aarch_vdso_symbol3 = "__vdso_clock_gettime"; \
	const char *aarch_vdso_symbol4 = "__vdso_gettimeofday";  \
	const char *aarch_vdso_symbol5 = "__vdso_rt_sigreturn";

#define ARCH_VDSO_SYMBOLS \
	aarch_vdso_symbol1, aarch_vdso_symbol2, aarch_vdso_symbol3, aarch_vdso_symbol4, aarch_vdso_symbol5
#endif
