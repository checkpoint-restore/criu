#ifndef COMPEL_ARCH_SYSCALL_TYPES_H__
#define COMPEL_ARCH_SYSCALL_TYPES_H__

/* Types for sigaction, sigprocmask syscalls */
typedef void rt_signalfn_t(int, siginfo_t *, void *);
typedef rt_signalfn_t *rt_sighandler_t;

typedef void rt_restorefn_t(void);
typedef rt_restorefn_t *rt_sigrestore_t;

#define SA_RESTORER 0x04000000

#define _KNSIG	  64
#define _NSIG_BPW 64

#define _KNSIG_WORDS (_KNSIG / _NSIG_BPW)

/*
 * Note: as k_rtsigset_t is the same size for 32-bit and 64-bit,
 * sig defined as uint64_t rather than (unsigned long) - for the
 * purpose if we ever going to support native 32-bit compilation.
 */
typedef struct {
	uint64_t sig[_KNSIG_WORDS];
} k_rtsigset_t;

typedef struct {
	rt_sighandler_t rt_sa_handler;
	unsigned long rt_sa_flags;
	rt_sigrestore_t rt_sa_restorer;
	k_rtsigset_t rt_sa_mask;
} rt_sigaction_t;

/*
 * Note: there is unaligned access on x86_64 and it's fine.
 * However, when porting this code -- keep in mind about possible issues
 * with unaligned rt_sa_mask.
 */
typedef struct __attribute__((packed)) {
	unsigned int rt_sa_handler;
	unsigned int rt_sa_flags;
	unsigned int rt_sa_restorer;
	k_rtsigset_t rt_sa_mask;
} rt_sigaction_t_compat;

/* Types for set_thread_area, get_thread_area syscalls */
typedef struct {
	unsigned int entry_number;
	unsigned int base_addr;
	unsigned int limit;
	unsigned int seg_32bit : 1;
	unsigned int contents : 2;
	unsigned int read_exec_only : 1;
	unsigned int limit_in_pages : 1;
	unsigned int seg_not_present : 1;
	unsigned int useable : 1;
	unsigned int lm : 1;
} user_desc_t;

#endif /* COMPEL_ARCH_SYSCALL_TYPES_H__ */
