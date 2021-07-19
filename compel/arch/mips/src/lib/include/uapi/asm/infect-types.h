#ifndef UAPI_COMPEL_ASM_TYPES_H__
#define UAPI_COMPEL_ASM_TYPES_H__

#include <stdint.h>
#include <stdbool.h>
#include <signal.h>
#include <compel/plugins/std/asm/syscall-types.h>
#include <linux/types.h>
#define SIGMAX	   64
#define SIGMAX_OLD 31

/*
 * Copied from the Linux kernel header arch/mips/include/asm/ptrace.h
 *
 * A thread MIPS CPU context
 */
typedef struct {
	/* Saved main processor registers. */
	__u64 regs[32];

	/* Saved special registers. */
	__u64 lo;
	__u64 hi;
	__u64 cp0_epc;
	__u64 cp0_badvaddr;
	__u64 cp0_status;
	__u64 cp0_cause;
} user_regs_struct_t;

/* from linux-3.10/arch/mips/kernel/ptrace.c */
typedef struct {
	/* Saved fpu registers. */
	__u64 regs[32];

	__u32 fpu_fcr31;
	__u32 fpu_id;

} user_fpregs_struct_t;

#define MIPS_a0 regs[4] //arguments a0-a3
#define MIPS_t0 regs[8] //temporaries t0-t7
#define MIPS_v0 regs[2]
#define MIPS_v1 regs[3]
#define MIPS_sp regs[29]
#define MIPS_ra regs[31]

#define NATIVE_MAGIC 0x0A
#define COMPAT_MAGIC 0x0C
static inline bool user_regs_native(user_regs_struct_t *pregs)
{
	return true;
}

#define __compel_arch_fetch_thread_area(tid, th) 0
#define compel_arch_fetch_thread_area(tctl)	 0
#define compel_arch_get_tls_task(ctl, tls)
#define compel_arch_get_tls_thread(tctl, tls)

#define REG_RES(regs)	     ((regs).MIPS_v0)
#define REG_IP(regs)	     ((regs).cp0_epc)
#define REG_SP(regs)	     ((regs).MIPS_sp)
#define REG_SYSCALL_NR(regs) ((regs).MIPS_v0)

//#define __NR(syscall, compat)	((compat) ? __NR32_##syscall : __NR_##syscall)
#define __NR(syscall, compat) __NR_##syscall

#endif /* UAPI_COMPEL_ASM_TYPES_H__ */
