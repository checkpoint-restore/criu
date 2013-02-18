#ifndef __CR_ASM_CPU_H__
#define __CR_ASM_CPU_H__

#include "asm/types.h"

/*
 * Adopted from linux kernel.
 */

#define NCAPINTS			(10)	/* N 32-bit words worth of info */
#define NCAPINTS_BITS			(NCAPINTS * 32)

#define X86_FEATURE_FPU			(0*32+ 0) /* Onboard FPU */
#define X86_FEATURE_FXSR		(0*32+24) /* FXSAVE/FXRSTOR, CR4.OSFXSR */
#define X86_FEATURE_XSAVE		(4*32+26) /* XSAVE/XRSTOR/XSETBV/XGETBV */

extern const char * const x86_cap_flags[NCAPINTS_BITS];

extern void cpu_set_feature(unsigned int feature);
extern bool cpu_has_feature(unsigned int feature);
extern int cpu_init(void);

#endif /* __CR_CPU_H__ */
