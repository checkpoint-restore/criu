#ifndef UAPI_COMPEL_ASM_TYPES_H__
#define UAPI_COMPEL_ASM_TYPES_H__

#include <stdint.h>
#include <signal.h>
#include <sys/mman.h>
#include <asm/ptrace.h>
#include "common/page.h"

#define SIGMAX	   64
#define SIGMAX_OLD 31

/*
 * Definitions from /usr/include/asm/ptrace.h:
 *
 * typedef struct
 * {
 *       __u32   fpc;
 *       freg_t  fprs[NUM_FPRS];
 * } s390_fp_regs;
 *
 * typedef struct
 * {
 *       psw_t psw;
 *       unsigned long gprs[NUM_GPRS];
 *       unsigned int  acrs[NUM_ACRS];
 *       unsigned long orig_gpr2;
 * } s390_regs;
 */
typedef struct {
	uint64_t part1;
	uint64_t part2;
} vector128_t;

struct prfpreg {
	uint32_t fpc;
	uint64_t fprs[16];
};

#define USER_FPREGS_VXRS 0x000000001
/* Guarded-storage control block */
#define USER_GS_CB 0x000000002
/* Guarded-storage broadcast control block */
#define USER_GS_BC 0x000000004
/* Runtime-instrumentation control block */
#define USER_RI_CB 0x000000008
/* Runtime-instrumentation bit set */
#define USER_RI_ON 0x000000010

typedef struct {
	uint32_t flags;
	struct prfpreg prfpreg;
	uint64_t vxrs_low[16];
	vector128_t vxrs_high[16];
	uint64_t gs_cb[4];
	uint64_t gs_bc[4];
	uint64_t ri_cb[8];
} user_fpregs_struct_t;

typedef struct {
	s390_regs prstatus;
	uint32_t system_call;
} user_regs_struct_t;

#define REG_RES(r) ((uint64_t)(r).prstatus.gprs[2])
#define REG_IP(r)  ((uint64_t)(r).prstatus.psw.addr)
#define REG_SP(r)  ((uint64_t)(r).prstatus.gprs[15])
/*
 * We assume that REG_SYSCALL_NR() is only used for pie code where we
 * always use svc 0 with opcode in %r1.
 */
#define REG_SYSCALL_NR(r) ((uint64_t)(r).prstatus.gprs[1])

#define user_regs_native(pregs) true

#define __NR(syscall, compat)   \
	({                      \
		(void)compat;   \
		__NR_##syscall; \
	})

struct mmap_arg_struct {
	unsigned long addr;
	unsigned long len;
	unsigned long prot;
	unsigned long flags;
	unsigned long fd;
	unsigned long offset;
};

#define __compel_arch_fetch_thread_area(tid, th) 0
#define compel_arch_fetch_thread_area(tctl)	 0
#define compel_arch_get_tls_task(ctl, tls)
#define compel_arch_get_tls_thread(tctl, tls)

#endif /* UAPI_COMPEL_ASM_TYPES_H__ */
