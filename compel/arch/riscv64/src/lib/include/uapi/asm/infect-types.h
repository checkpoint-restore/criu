#ifndef UAPI_COMPEL_ASM_TYPES_H__
#define UAPI_COMPEL_ASM_TYPES_H__

#include <stdint.h>
#include <signal.h>
#include <sys/mman.h>
#include <asm/ptrace.h>

#define SIGMAX	   64
#define SIGMAX_OLD 31

/*
 * Copied from the Linux kernel header arch/riscv/include/uapi/asm/ptrace.h
 *
 * A thread RISC-V CPU context
 */
typedef struct user_regs_struct user_regs_struct_t;
typedef struct __riscv_d_ext_state user_fpregs_struct_t;

#define __compel_arch_fetch_thread_area(tid, th) 0
#define compel_arch_fetch_thread_area(tctl)	 0
#define compel_arch_get_tls_task(ctl, tls)
#define compel_arch_get_tls_thread(tctl, tls)

#define REG_RES(registers)	   ((uint64_t)(registers).a0)
#define REG_IP(registers)	   ((uint64_t)(registers).pc)
#define SET_REG_IP(registers, val) ((registers).pc = (val))

/*
 * REG_SP is also defined in riscv64-linux-gnu/include/sys/ucontext.h
 * with a different meaning, and it's not used in CRIU. So we have to
 * undefine it here.
 */
#ifdef REG_SP
#undef REG_SP
#endif

#define REG_SP(registers) ((uint64_t)((registers).sp))

#define REG_SYSCALL_NR(registers) ((uint64_t)(registers).a7)

#define user_regs_native(pregs) true

#define ARCH_SI_TRAP TRAP_BRKPT

#define __NR(syscall, compat)   \
	({                      \
		(void)compat;   \
		__NR_##syscall; \
	})

#endif /* UAPI_COMPEL_ASM_TYPES_H__ */