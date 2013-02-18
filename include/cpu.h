#ifndef __CR_CPU_H__
#define __CR_CPU_H__

#include "asm/cpu.h"

extern void cpu_set_feature(unsigned int feature);
extern bool cpu_has_feature(unsigned int feature);
extern int cpu_init(void);

#endif /* __CR_CPU_H__ */
