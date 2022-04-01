#ifndef UAPI_COMPEL_ASM_TYPES_H__
#define UAPI_COMPEL_ASM_TYPES_H__

#include <stdint.h>
#include <signal.h>
#include <sys/mman.h>
#include <asm/ptrace.h>

#define SIGMAX	   64
#define SIGMAX_OLD 31

/*
 * Copied from the Linux kernel header arch/arm64/include/uapi/asm/ptrace.h
 *
 * A thread ARM CPU context
 */


typedef struct user_regs_struct user_regs_struct_t;
typedef struct __riscv_d_ext_state user_fpregs_struct_t;

#define __compel_arch_fetch_thread_area(tid, th) 0
#define compel_arch_fetch_thread_area(tctl)	 0
#define compel_arch_get_tls_task(ctl, tls)
#define compel_arch_get_tls_thread(tctl, tls)

#define REG_RES(r)	  ((uint64_t)(r).a0)
#define REG_IP(r)	  ((uint64_t)(r).pc)

// #ifndef REG_SP
#define REG_GET_SP(r)	  ((uint64_t)((r).sp))
// #endif

#define REG_SYSCALL_NR(r) ((uint64_t)(r).a7)

#define user_regs_native(pregs) true

#define ARCH_SI_TRAP TRAP_BRKPT

#define __NR(syscall, compat)   \
	({                      \
		(void)compat;   \
		__NR_##syscall; \
	})

#endif /* UAPI_COMPEL_ASM_TYPES_H__ */
