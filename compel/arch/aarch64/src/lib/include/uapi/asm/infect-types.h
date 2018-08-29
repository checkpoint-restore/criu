#ifndef UAPI_COMPEL_ASM_TYPES_H__
#define UAPI_COMPEL_ASM_TYPES_H__

#include <stdint.h>
#include <signal.h>
#include <sys/mman.h>
#include <asm/ptrace.h>

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
#define REG_SP(r)			((uint64_t)((r).sp))
#define REG_SYSCALL_NR(r)		((uint64_t)(r).regs[8])

#define user_regs_native(pregs)			true

#define ARCH_SI_TRAP		TRAP_BRKPT

#define __NR(syscall, compat)	__NR_##syscall

#endif /* UAPI_COMPEL_ASM_TYPES_H__ */
