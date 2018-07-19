#ifndef UAPI_COMPEL_CPU_H__
#define UAPI_COMPEL_CPU_H__

#include <stdbool.h>
#include <stdint.h>

#include <compel/asm/cpu.h>

extern int compel_cpuid(compel_cpuinfo_t *info);
extern bool compel_cpu_has_feature(unsigned int feature);
extern bool compel_fpu_has_feature(unsigned int feature);
extern uint32_t compel_fpu_feature_size(unsigned int feature);
extern uint32_t compel_fpu_feature_offset(unsigned int feature);
extern void compel_cpu_clear_feature(unsigned int feature);
extern void compel_cpu_copy_cpuinfo(compel_cpuinfo_t *c);

#endif /* UAPI_COMPEL_CPU_H__ */
