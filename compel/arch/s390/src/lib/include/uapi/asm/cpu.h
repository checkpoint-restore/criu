#ifndef UAPI_COMPEL_ASM_CPU_H__
#define UAPI_COMPEL_ASM_CPU_H__

#include <stdint.h>

typedef struct {
	uint64_t hwcap[2];
} compel_cpuinfo_t;

#endif /* __CR_ASM_CPU_H__ */
