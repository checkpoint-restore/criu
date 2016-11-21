#ifndef UAPI_COMPEL_ASM_TYPES_H__
#define UAPI_COMPEL_ASM_TYPES_H__

#include <stdint.h>
#include <signal.h>
#include <sys/mman.h>
#include <asm/ptrace.h>
#include "common/page.h"

#define SIGMAX			64
#define SIGMAX_OLD		31

/*
 * Copied from the Linux kernel header arch/arm64/include/uapi/asm/ptrace.h
 *
 * A thread ARM CPU context
 */

typedef struct user_pt_regs		user_regs_struct_t;
typedef struct user_fpsimd_state	user_fpregs_struct_t;

#define REG_RES(r)			((uint64_t)(r).regs[0])
#define REG_IP(r)			((uint64_t)(r).pc)
#define REG_SYSCALL_NR(r)		((uint64_t)(r).regs[8])

/*
 * Range for task size calculated from the following Linux kernel files:
 *   arch/arm64/include/asm/memory.h
 *   arch/arm64/Kconfig
 *
 * TODO: handle 32 bit tasks
 */
#define TASK_SIZE_MIN (1UL << 39)
#define TASK_SIZE_MAX (1UL << 48)

static inline unsigned long task_size(void)
{
	unsigned long task_size;

	for (task_size = TASK_SIZE_MIN; task_size < TASK_SIZE_MAX; task_size <<= 1)
		if (munmap((void *)task_size, page_size()))
			break;
	return task_size;
}

#define AT_VECTOR_SIZE 40

typedef uint64_t auxv_t;
typedef uint64_t tls_t;

#define ARCH_SI_TRAP		TRAP_BRKPT

#define __NR(syscall, compat)	__NR_##syscall

#endif /* UAPI_COMPEL_ASM_TYPES_H__ */
