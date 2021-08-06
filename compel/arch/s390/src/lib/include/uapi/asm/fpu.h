#ifndef __CR_ASM_FPU_H__
#define __CR_ASM_FPU_H__

#include <stdbool.h>
#include <sys/types.h>

/*
 * This one is used in restorer
 */
typedef struct {
	bool has_fpu;
} fpu_state_t;

#endif /* __CR_ASM_FPU_H__ */
