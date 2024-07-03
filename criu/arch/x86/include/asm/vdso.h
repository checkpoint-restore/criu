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
#define VDSO_SYMBOL_MAX	 7
#define VDSO_SYMBOL_GTOD 2

/*
 * XXX: we don't patch __kernel_vsyscall as it's too small:
 *
 *   byte	*before*		*after*
 *   0x0	push   %ecx		mov    $[rt-vdso],%eax
 *   0x1	push   %edx		^
 *   0x2	push   %ebp		^
 *   0x3	mov    %esp,%ebp	^
 *   0x5	sysenter		jmp    *%eax
 *   0x7	int    $0x80		int3
 *   0x9	pop    %ebp		int3
 *   0xa	pop    %edx		int3
 *   0xb	pop    %ecx		pop    %ecx
 *   0xc	ret			ret
 *
 * As restarting a syscall is quite likely after restore,
 * the patched version quitly crashes.
 * vsyscall will be patched again when addressing:
 * https://github.com/checkpoint-restore/criu/issues/512
 */

#define ARCH_VDSO_SYMBOLS_LIST                                   \
	const char *aarch_vdso_symbol1 = "__vdso_clock_gettime"; \
	const char *aarch_vdso_symbol2 = "__vdso_getcpu";        \
	const char *aarch_vdso_symbol3 = "__vdso_gettimeofday";  \
	const char *aarch_vdso_symbol4 = "__vdso_time";          \
	const char *aarch_vdso_symbol5 = "__kernel_sigreturn";   \
	const char *aarch_vdso_symbol6 = "__kernel_rt_sigreturn"; \
	const char *aarch_vdso_symbol7 = "__vdso_clock_gettime64"; \

#define ARCH_VDSO_SYMBOLS                                                                                   \
	aarch_vdso_symbol1, aarch_vdso_symbol2, aarch_vdso_symbol3, aarch_vdso_symbol4, aarch_vdso_symbol5, \
		aarch_vdso_symbol6, aarch_vdso_symbol7

/*	"__kernel_vsyscall",			*/

#ifndef ARCH_MAP_VDSO_32
#define ARCH_MAP_VDSO_32 0x2002
#endif

#ifndef ARCH_MAP_VDSO_64
#define ARCH_MAP_VDSO_64 0x2003
#endif

#if defined(CONFIG_COMPAT) && !defined(__ASSEMBLY__)
struct vdso_symtable;
extern int vdso_fill_symtable(uintptr_t mem, size_t size, struct vdso_symtable *t);
extern int vdso_fill_symtable_compat(uintptr_t mem, size_t size, struct vdso_symtable *t);

static inline int __vdso_fill_symtable(uintptr_t mem, size_t size, struct vdso_symtable *t, bool compat_vdso)
{
	if (compat_vdso)
		return vdso_fill_symtable_compat(mem, size, t);
	else
		return vdso_fill_symtable(mem, size, t);
}
#endif

#endif /* __CR_ASM_VDSO_H__ */
