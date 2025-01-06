#ifndef __COMPEL_CPU_H__
#define __COMPEL_CPU_H__

#include <compel/cpu.h>
#include "asm/cpu.h"

extern void compel_set_cpu_cap(compel_cpuinfo_t *info, unsigned int feature);
extern void compel_clear_cpu_cap(compel_cpuinfo_t *info, unsigned int feature);
extern int compel_test_cpu_cap(compel_cpuinfo_t *info, unsigned int feature);
extern int compel_test_fpu_cap(compel_cpuinfo_t *c, unsigned int feature);

#endif
