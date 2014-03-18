#ifndef __CR_ASM_TYPES_H__
#define __CR_ASM_TYPES_H__

#include <stdbool.h>
#include <signal.h>

#include "asm-generic/page.h"
#include "asm/bitops.h"
#include "asm/int.h"
#include "asm/prlimit.h"

#include "protobuf/core.pb-c.h"

#define SIGMAX			64
#define SIGMAX_OLD		31

#define MAJOR(dev)		((dev)>>8)
#define MINOR(dev)		((dev) & 0xff)

typedef void rt_signalfn_t(int, siginfo_t *, void *);
typedef rt_signalfn_t *rt_sighandler_t;

typedef void rt_restorefn_t(void);
typedef rt_restorefn_t *rt_sigrestore_t;

#define _KNSIG           64
# define _NSIG_BPW      64

#define _KNSIG_WORDS     (_KNSIG / _NSIG_BPW)

typedef struct {
	unsigned long sig[_KNSIG_WORDS];
} k_rtsigset_t;

static inline void ksigfillset(k_rtsigset_t *set)
{
	int i;
	for (i = 0; i < _KNSIG_WORDS; i++)
		set->sig[i] = (unsigned long)-1;
}

#define SA_RESTORER	0x04000000

typedef struct {
	rt_sighandler_t	rt_sa_handler;
	unsigned long	rt_sa_flags;
	rt_sigrestore_t	rt_sa_restorer;
	k_rtsigset_t	rt_sa_mask;
} rt_sigaction_t;

typedef struct {
	unsigned int	entry_number;
	unsigned int	base_addr;
	unsigned int	limit;
	unsigned int	seg_32bit:1;
	unsigned int	contents:2;
	unsigned int	read_exec_only:1;
	unsigned int	limit_in_pages:1;
	unsigned int	seg_not_present:1;
	unsigned int	useable:1;
	unsigned int	lm:1;
} user_desc_t;

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

#define ASSIGN_TYPED(a, b) do { a = (typeof(a))b; } while (0)
#define ASSIGN_MEMBER(a,b,m) do { ASSIGN_TYPED((a)->m, (b)->m); } while (0)

#define TASK_SIZE ((1UL << 47) - PAGE_SIZE)

typedef u64 auxv_t;
typedef u32 tls_t;

#define REG_RES(regs) ((regs).ax)
#define REG_IP(regs)  ((regs).ip)
#define REG_SYSCALL_NR(regs)	((regs).orig_ax)

#define CORE_ENTRY__MARCH CORE_ENTRY__MARCH__X86_64

#define AT_VECTOR_SIZE 44

#define CORE_THREAD_ARCH_INFO(core) core->thread_info

typedef UserX86RegsEntry UserRegsEntry;

static inline u64 encode_pointer(void *p) { return (u64)p; }
static inline void *decode_pointer(u64 v) { return (void*)v; }

#endif /* __CR_ASM_TYPES_H__ */
