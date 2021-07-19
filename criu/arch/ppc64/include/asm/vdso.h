#ifndef __CR_ASM_VDSO_H__
#define __CR_ASM_VDSO_H__

#include "asm/int.h"
#include "asm-generic/vdso.h"

/* This definition is used in pie/util-vdso.c to initialize the vdso symbol
 * name string table 'vdso_symbols'
 *
 * Poke from kernel file arch/powerpc/kernel/vdso64/vdso64.lds.S
 *
 * Note that '__kernel_datapage_offset' is not a service but mostly a data
 * inside the text page which should not be used as is from user space.
 */
#define VDSO_SYMBOL_MAX	 10
#define VDSO_SYMBOL_GTOD 5
#define ARCH_VDSO_SYMBOLS_LIST                                       \
	const char *aarch_vdso_symbol1 = "__kernel_clock_getres";    \
	const char *aarch_vdso_symbol2 = "__kernel_clock_gettime";   \
	const char *aarch_vdso_symbol3 = "__kernel_get_syscall_map"; \
	const char *aarch_vdso_symbol4 = "__kernel_get_tbfreq";      \
	const char *aarch_vdso_symbol5 = "__kernel_getcpu";          \
	const char *aarch_vdso_symbol6 = "__kernel_gettimeofday";    \
	const char *aarch_vdso_symbol7 = "__kernel_sigtramp_rt64";   \
	const char *aarch_vdso_symbol8 = "__kernel_sync_dicache";    \
	const char *aarch_vdso_symbol9 = "__kernel_sync_dicache_p5"; \
	const char *aarch_vdso_symbol10 = "__kernel_time";

#define ARCH_VDSO_SYMBOLS                                                                                   \
	aarch_vdso_symbol1, aarch_vdso_symbol2, aarch_vdso_symbol3, aarch_vdso_symbol4, aarch_vdso_symbol5, \
		aarch_vdso_symbol6, aarch_vdso_symbol7, aarch_vdso_symbol8, aarch_vdso_symbol9, aarch_vdso_symbol10

#endif /* __CR_ASM_VDSO_H__ */
