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
#define VDSO_SYMBOL_MAX	3
#define VDSO_SYMBOL_GTOD	0
#define ARCH_VDSO_SYMBOLS_LIST \
	const char* aarch_vdso_symbol1 = "__vdso_clock_gettime"; \
	const char* aarch_vdso_symbol2 = "__vdso_gettimeofday"; \
	const char* aarch_vdso_symbol3 = "__vdso_clock_getres";
#define ARCH_VDSO_SYMBOLS \
	aarch_vdso_symbol1, \
	aarch_vdso_symbol2, \
	aarch_vdso_symbol3,


#endif /* __CR_ASM_VDSO_H__ */
