#ifndef UAPI_COMPEL_ASM_TYPES_H__
#define UAPI_COMPEL_ASM_TYPES_H__

#include <stdint.h>
#include <stdbool.h>
#include <signal.h>
#include "log.h"
#include "common/bug.h"
#include "common/page.h"
#include "syscall-types.h"

#define SIGMAX			64
#define SIGMAX_OLD		31

typedef struct {
	uint64_t	r15;
	uint64_t	r14;
	uint64_t	r13;
	uint64_t	r12;
	uint64_t	bp;
	uint64_t	bx;
	uint64_t	r11;
	uint64_t	r10;
	uint64_t	r9;
	uint64_t	r8;
	uint64_t	ax;
	uint64_t	cx;
	uint64_t	dx;
	uint64_t	si;
	uint64_t	di;
	uint64_t	orig_ax;
	uint64_t	ip;
	uint64_t	cs;
	uint64_t	flags;
	uint64_t	sp;
	uint64_t	ss;
	uint64_t	fs_base;
	uint64_t	gs_base;
	uint64_t	ds;
	uint64_t	es;
	uint64_t	fs;
	uint64_t	gs;
} user_regs_struct64;

typedef struct {
	uint32_t	bx;
	uint32_t	cx;
	uint32_t	dx;
	uint32_t	si;
	uint32_t	di;
	uint32_t	bp;
	uint32_t	ax;
	uint32_t	ds;
	uint32_t	es;
	uint32_t	fs;
	uint32_t	gs;
	uint32_t	orig_ax;
	uint32_t	ip;
	uint32_t	cs;
	uint32_t	flags;
	uint32_t	sp;
	uint32_t	ss;
} user_regs_struct32;

#ifdef CONFIG_X86_64
/*
 * To be sure that we rely on inited reg->__is_native, this member
 * is (short int) instead of initial (bool). The right way to
 * check if regs are native or compat is to use user_regs_native() macro.
 * This should cost nothing, as *usually* sizeof(bool) == sizeof(short)
 */
typedef struct {
	union {
		user_regs_struct64 native;
		user_regs_struct32 compat;
	};
	short __is_native; /* use user_regs_native macro to check it */
} user_regs_struct_t;

#define NATIVE_MAGIC	0x0A
#define COMPAT_MAGIC	0x0C
static inline bool user_regs_native(user_regs_struct_t *pregs)
{
	return pregs->__is_native == NATIVE_MAGIC;
}

#define get_user_reg(pregs, name)			\
	((user_regs_native(pregs))		?	\
	 ((pregs)->native.name)			:	\
	 ((pregs)->compat.name))

#define set_user_reg(pregs, name, val)			\
	((user_regs_native(pregs))		?	\
	 ((pregs)->native.name = (val))		:	\
	 ((pregs)->compat.name = (val)))
#else
typedef struct {
	union {
		user_regs_struct32 native;
	};
} user_regs_struct_t;
#define user_regs_native(pregs)		true
#define get_user_reg(pregs, name)	((pregs)->native.name)
#define set_user_reg(pregs, name, val)	((pregs)->native.name = val)
#endif

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

/*
 * Linux preserves three TLS segments in GDT.
 * Offsets in GDT differ between 32-bit and 64-bit machines.
 * For 64-bit x86 those GDT offsets are the same
 * for native and compat tasks.
 */
#define GDT_ENTRY_TLS_MIN		12
#define GDT_ENTRY_TLS_MAX		14
#define GDT_ENTRY_TLS_NUM		3
typedef struct {
	user_desc_t desc[GDT_ENTRY_TLS_NUM];
} tls_t;

#define REG_RES(regs)		get_user_reg(&regs, ax)
#define REG_IP(regs)		get_user_reg(&regs, ip)
#define REG_SYSCALL_NR(regs)	get_user_reg(&regs, orig_ax)

#define AT_VECTOR_SIZE 44

#endif /* UAPI_COMPEL_ASM_TYPES_H__ */
