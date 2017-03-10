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
#define VDSO_SYMBOL_MAX		10
#define ARCH_VDSO_SYMBOLS			\
	"__kernel_clock_getres",		\
	"__kernel_clock_gettime",		\
	"__kernel_get_syscall_map",		\
	"__kernel_get_tbfreq",			\
	"__kernel_getcpu",			\
	"__kernel_gettimeofday",		\
	"__kernel_sigtramp_rt64",		\
	"__kernel_sync_dicache",		\
	"__kernel_sync_dicache_p5",		\
	"__kernel_time"

#endif /* __CR_ASM_VDSO_H__ */
