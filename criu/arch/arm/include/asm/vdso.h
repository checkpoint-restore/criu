#ifndef __CR_ASM_VDSO_H__
#define __CR_ASM_VDSO_H__

#include "asm/int.h"
#include "asm-generic/vdso.h"

/* This definition is used in pie/util-vdso.c to initialize the vdso symbol
 * name string table 'vdso_symbols'
 *
 * Poke from kernel file arch/arm/vdso/vdso.lds.S
 */
#define VDSO_SYMBOL_MAX	 2
#define VDSO_SYMBOL_GTOD 1
#define ARCH_VDSO_SYMBOLS_LIST                                   \
	const char *aarch_vdso_symbol1 = "__vdso_clock_gettime"; \
	const char *aarch_vdso_symbol2 = "__vdso_gettimeofday";
#define ARCH_VDSO_SYMBOLS aarch_vdso_symbol1, aarch_vdso_symbol2,

#endif /* __CR_ASM_VDSO_H__ */
