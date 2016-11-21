#ifndef UAPI_COMPEL_ASM_TYPES_H__
#define UAPI_COMPEL_ASM_TYPES_H__

#include <stdint.h>
#include <stdbool.h>
#include <signal.h>
#include "common/page.h"
#include "syscall-types.h"

#define SIGMAX			64
#define SIGMAX_OLD		31

typedef struct {
	unsigned long	r15;
	unsigned long	r14;
	unsigned long	r13;
	unsigned long	r12;
	unsigned long	bp;
	unsigned long	bx;
	unsigned long	r11;
	unsigned long	r10;
	unsigned long	r9;
	unsigned long	r8;
	unsigned long	ax;
	unsigned long	cx;
	unsigned long	dx;
	unsigned long	si;
	unsigned long	di;
	unsigned long	orig_ax;
	unsigned long	ip;
	unsigned long	cs;
	unsigned long	flags;
	unsigned long	sp;
	unsigned long	ss;
	unsigned long	fs_base;
	unsigned long	gs_base;
	unsigned long	ds;
	unsigned long	es;
	unsigned long	fs;
	unsigned long	gs;
} user_regs_struct_t;

#if 0
typedef struct {
	unsigned short	cwd;
	unsigned short	swd;
	unsigned short	twd;	/* Note this is not the same as
				   the 32bit/x87/FSAVE twd */
	unsigned short	fop;
	u64		rip;
	u64		rdp;
	u32		mxcsr;
	u32		mxcsr_mask;
	u32		st_space[32];	/* 8*16 bytes for each FP-reg = 128 bytes */
	u32		xmm_space[64];	/* 16*16 bytes for each XMM-reg = 256 bytes */
	u32		padding[24];
} user_fpregs_struct_t;
#endif

typedef struct xsave_struct user_fpregs_struct_t;

#ifdef CONFIG_X86_64
# define TASK_SIZE	((1UL << 47) - PAGE_SIZE)
#else
/*
 * Task size may be limited to 3G but we need a
 * higher limit, because it's backward compatible.
 */
# define TASK_SIZE	(0xffffe000)
#endif

static inline unsigned long task_size(void) { return TASK_SIZE; }

typedef uint64_t auxv_t;
typedef uint32_t tls_t;

#define REG_RES(regs) ((regs).ax)
#define REG_IP(regs)  ((regs).ip)
#define REG_SYSCALL_NR(regs)	((regs).orig_ax)

#define AT_VECTOR_SIZE 44

#endif /* UAPI_COMPEL_ASM_TYPES_H__ */
