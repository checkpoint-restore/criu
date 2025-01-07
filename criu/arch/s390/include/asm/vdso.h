#ifndef __CR_ASM_VDSO_H__
#define __CR_ASM_VDSO_H__

#include "asm/int.h"
#include "asm-generic/vdso.h"

/*
 * This is a minimal amount of symbols
 * we should support at the moment.
 */
#define VDSO_SYMBOL_MAX	 4
#define VDSO_SYMBOL_GTOD 0

/*
 * These definitions are used in pie/util-vdso.c to initialize the vdso symbol
 * name string table 'vdso_symbols'
 */
#define ARCH_VDSO_SYMBOLS_LIST                                     \
	const char *aarch_vdso_symbol1 = "__kernel_gettimeofday";  \
	const char *aarch_vdso_symbol2 = "__kernel_clock_gettime"; \
	const char *aarch_vdso_symbol3 = "__kernel_clock_getres";  \
	const char *aarch_vdso_symbol4 = "__kernel_getcpu";
#define ARCH_VDSO_SYMBOLS aarch_vdso_symbol1, aarch_vdso_symbol2, aarch_vdso_symbol3, aarch_vdso_symbol4

#endif /* __CR_ASM_VDSO_H__ */
