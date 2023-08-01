#ifndef __CR_ASM_VDSO_H__
#define __CR_ASM_VDSO_H__

#include "asm/int.h"
#include "common/compiler.h"
#include "asm-generic/vdso.h"

/*
 * This is a minimal amount of symbols
 * we should support at the moment.
 */
#define VDSO_SYMBOL_MAX	 6
#define VDSO_SYMBOL_GTOD 2

#define ARCH_VDSO_SYMBOLS_LIST                                  \
	const char *rv64_vdso_symbol1 = "__vdso_clock_getres";  \
	const char *rv64_vdso_symbol2 = "__vdso_clock_gettime"; \
	const char *rv64_vdso_symbol3 = "__vdso_gettimeofday";  \
	const char *rv64_vdso_symbol4 = "__vdso_getcpu";        \
	const char *rv64_vdso_symbol5 = "__vdso_flush_icache";  \
	const char *rv64_vdso_symbol6 = "__vdso_rt_sigreturn";

#define ARCH_VDSO_SYMBOLS \
	rv64_vdso_symbol1, rv64_vdso_symbol2, rv64_vdso_symbol3, rv64_vdso_symbol4, rv64_vdso_symbol5, rv64_vdso_symbol6

extern void write_intraprocedure_branch(unsigned long to, unsigned long from);

#endif /* __CR_ASM_VDSO_H__ */