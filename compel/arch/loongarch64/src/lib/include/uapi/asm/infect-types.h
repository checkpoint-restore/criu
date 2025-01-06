#ifndef UAPI_COMPEL_ASM_TYPES_H__
#define UAPI_COMPEL_ASM_TYPES_H__

#include <stdint.h>

#define SIGMAX	   64
#define SIGMAX_OLD 31

/*
 * From the Linux kernel header arch/loongarch/include/uapi/asm/ptrace.h
 *
 * A thread LoongArch CPU context
 *
 * struct user_fp_state {
 *     uint64_t    fpr[32];
 *     uint64_t    fcc;
 *     uint32_t    fcsr;
 * };
 *
 * struct user_pt_regs {
 *     unsigned long regs[32];
 *     unsigned long csr_era;
 *     unsigned long csr_badv;
 *     unsigned long reserved[11];
 * };
 */

struct user_gp_regs {
	uint64_t regs[32];
	uint64_t orig_a0;
	uint64_t pc;
	uint64_t csr_badv;
	uint64_t reserved[10];
} __attribute__((aligned(8)));

struct user_fp_regs {
	uint64_t regs[32];
	uint64_t fcc;
	uint32_t fcsr;
};

typedef struct user_gp_regs user_regs_struct_t;
typedef struct user_fp_regs user_fpregs_struct_t;

#define user_regs_native(regs) true

#define __compel_arch_fetch_thread_area(tid, th) 0
#define compel_arch_fetch_thread_area(tctl)	 0
#define compel_arch_get_tls_task(ctl, tls)
#define compel_arch_get_tls_thread(tctl, tls)

#define REG_RES(r)	   ((uint64_t)(r).regs[4])
#define REG_IP(r)	   ((uint64_t)(r).pc)
#define REG_SP(r)	   ((uint64_t)(r).regs[3])
#define REG_SYSCALL_NR(r)  ((uint64_t)(r).regs[11])
#define SET_REG_IP(r, val) ((r).pc = (val))

#define GPR_NUM 32
#define FPR_NUM 32

#define __NR(syscall, compat)   \
	({                      \
		(void)compat;   \
		__NR_##syscall; \
	})

#endif /* UAPI_COMPEL_ASM_TYPES_H__ */
