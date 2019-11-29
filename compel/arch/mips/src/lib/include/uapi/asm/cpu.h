#ifndef __CR_ASM_CPU_H__
#define __CR_ASM_CPU_H__

#include <stdint.h>

/*
 * Adopted from linux kernel and enhanced from Intel/AMD manuals.
 */

#define NCAPINTS			(12) /* N 32-bit words worth of info */
#define NCAPINTS_BITS			(NCAPINTS * 32)

typedef struct { } compel_cpuinfo_t;
#endif /* __CR_ASM_CPU_H__ */
