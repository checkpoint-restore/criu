#ifndef __CR_ASM_TYPES_H__
#define __CR_ASM_TYPES_H__

#include <stdint.h>
#include <stdbool.h>
#include <signal.h>
#include "protobuf/core.pb-c.h"

#include "asm/bitops.h"

/* prctl.h */
#define PR_SET_NAME		15
#define PR_GET_NAME		16

#define PR_CAPBSET_DROP		24
#define PR_GET_SECUREBITS	27
#define PR_SET_SECUREBITS	28

#define SECURE_NO_SETUID_FIXUP	2

#define PR_SET_MM		35
# define PR_SET_MM_START_CODE		1
# define PR_SET_MM_END_CODE		2
# define PR_SET_MM_START_DATA		3
# define PR_SET_MM_END_DATA		4
# define PR_SET_MM_START_STACK		5
# define PR_SET_MM_START_BRK		6
# define PR_SET_MM_BRK			7
# define PR_SET_MM_ARG_START		8
# define PR_SET_MM_ARG_END		9
# define PR_SET_MM_ENV_START		10
# define PR_SET_MM_ENV_END		11
# define PR_SET_MM_AUXV			12
# define PR_SET_MM_EXE_FILE		13

#define PR_GET_TID_ADDRESS     40

/* fcntl */
#ifndef F_LINUX_SPECIFIC_BASE
#define F_LINUX_SPECIFIC_BASE	1024
#endif
#ifndef F_SETPIPE_SZ
# define F_SETPIPE_SZ	(F_LINUX_SPECIFIC_BASE + 7)
#endif
#ifndef F_GETPIPE_SZ
# define F_GETPIPE_SZ	(F_LINUX_SPECIFIC_BASE + 8)
#endif

#ifndef F_GETOWNER_UIDS
#define F_GETOWNER_UIDS	17
#endif

#define CLONE_CHILD_USEPID      0x02000000
#define CLONE_VFORK		0x00004000

#define SIGMAX			64
#define SIGMAX_OLD		31

#define ERESTARTSYS		512
#define ERESTARTNOINTR		513
#define ERESTARTNOHAND		514
#define ERESTART_RESTARTBLOCK	516

typedef uint64_t		u64;
typedef int64_t			s64;
typedef unsigned int		u32;
typedef signed int		s32;
typedef unsigned short		u16;
typedef signed short		s16;
typedef unsigned char		u8;
typedef signed char		s8;

#define MAJOR(dev)		((dev)>>8)
#define MINOR(dev)		((dev) & 0xff)

#define _LINUX_CAPABILITY_VERSION_3	0x20080522
#define _LINUX_CAPABILITY_U32S_3	2


typedef struct {
	unsigned long sig[2];
} rt_sigset_t;

typedef void rt_signalfn_t(int, siginfo_t *, void *);
typedef rt_signalfn_t *rt_sighandler_t;

typedef void rt_restorefn_t(void);
typedef rt_restorefn_t *rt_sigrestore_t;

typedef struct {
	rt_sighandler_t	rt_sa_handler;
	unsigned long	rt_sa_flags;
	rt_sigrestore_t	rt_sa_restorer;
	rt_sigset_t	rt_sa_mask;
} rt_sigaction_t;

#define _KNSIG		64
#define _NSIG_BPW	32

#define _KNSIG_WORDS	(_KNSIG / _NSIG_BPW)

typedef struct {
	unsigned long sig[_KNSIG_WORDS];
} k_rtsigset_t;

static inline void ksigfillset(k_rtsigset_t *set)
{
	int i;
	for (i = 0; i < _KNSIG_WORDS; i++)
		set->sig[i] = (unsigned long)-1;
}


/*
 * Copied from the Linux kernel header arch/arm/include/asm/ptrace.h
 *
 * A thread ARM CPU context
 */

typedef struct {
        long uregs[18];
} user_regs_struct_t;

#define ARM_cpsr        uregs[16]
#define ARM_pc          uregs[15]
#define ARM_lr          uregs[14]
#define ARM_sp          uregs[13]
#define ARM_ip          uregs[12]
#define ARM_fp          uregs[11]
#define ARM_r10         uregs[10]
#define ARM_r9          uregs[9]
#define ARM_r8          uregs[8]
#define ARM_r7          uregs[7]
#define ARM_r6          uregs[6]
#define ARM_r5          uregs[5]
#define ARM_r4          uregs[4]
#define ARM_r3          uregs[3]
#define ARM_r2          uregs[2]
#define ARM_r1          uregs[1]
#define ARM_r0          uregs[0]
#define ARM_ORIG_r0     uregs[17]


/* Copied from arch/arm/include/asm/user.h */

struct user_vfp {
	unsigned long long fpregs[32];
	unsigned long fpscr;
};

struct user_vfp_exc {
        unsigned long   fpexc;
	unsigned long   fpinst;
	unsigned long   fpinst2;
};

#define ASSIGN_TYPED(a, b) do { a = (typeof(a))b; } while (0)
#define ASSIGN_MEMBER(a,b,m) do { ASSIGN_TYPED((a)->m, (b)->m); } while (0)

#ifndef PAGE_SIZE
# define PAGE_SIZE	4096
#endif

#ifndef PAGE_MASK
# define PAGE_MASK	(~(PAGE_SIZE - 1))
#endif

/* For sys_kcmp */
enum kcmp_type {
	KCMP_FILE,
	KCMP_VM,
	KCMP_FILES,
	KCMP_FS,
	KCMP_SIGHAND,
	KCMP_IO,
	KCMP_SYSVSEM,

	KCMP_TYPES,
};

/* For UNIX sockets data */
#ifndef SCM_MAX_FD
# define SCM_MAX_FD	253
#endif

#include <fcntl.h>

#ifndef F_SETOWN_EX
#define F_SETOWN_EX	15
#define F_GETOWN_EX	16

struct f_owner_ex {
	int	type;
	pid_t	pid;
};
#endif

/* File handle */
typedef struct {
	u32 bytes;
	u32 type;
	u64 __handle[16];
} fh_t;

#ifndef MAP_HUGETLB
# define MAP_HUGETLB 0x40000
#endif

#ifndef MADV_HUGEPAGE
# define MADV_HUGEPAGE 14
#endif

#ifndef MADV_NOHUGEPAGE
# define MADV_NOHUGEPAGE 15
#endif

#ifndef MADV_DONTDUMP
# define MADV_DONTDUMP 16
#endif

#define REG_RES(regs) ((regs).ARM_r0)
#define REG_IP(regs)  ((regs).ARM_pc)

#define TASK_SIZE 0xbf000000

#define AT_VECTOR_SIZE 40

typedef UserArmRegsEntry UserRegsEntry;

#define CORE_ENTRY__MARCH CORE_ENTRY__MARCH__ARM

#define CORE_THREAD_ARCH_INFO(core) core->ti_arm

#define TI_SP(core) ((core)->ti_arm->gpregs->sp)

typedef uint32_t auxv_t;

static inline void *decode_pointer(uint64_t v) { return (void*)(uint32_t)v; }
static inline uint64_t encode_pointer(void *p) { return (uint32_t)p; }

#define BITS_PER_ULONG 32

typedef struct {
	struct user_vfp		ufp;
	struct user_vfp_exc	ufp_exc;
} fpu_state_t;

#endif /* __CR_ASM_TYPES_H__ */
