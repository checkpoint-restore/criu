#ifndef __CR_CPU_H__
#define __CR_CPU_H__

#include "asm/cpu.h"

extern bool cpu_has_feature(unsigned int feature);
extern int cpu_init(void);
extern int cpu_dump_cpuinfo(void);
extern int cpu_validate_cpuinfo(void);
extern int cpuinfo_dump(void);
extern int cpuinfo_check(void);

#endif /* __CR_CPU_H__ */
