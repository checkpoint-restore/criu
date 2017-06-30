#ifndef COMPEL_ARCH_SYSCALL_TYPES_H__
#define COMPEL_ARCH_SYSCALL_TYPES_H__

#define SA_RESTORER     0x04000000U

typedef void rt_signalfn_t(int, siginfo_t *, void *);
typedef rt_signalfn_t *rt_sighandler_t;

typedef void rt_restorefn_t(void);
typedef rt_restorefn_t *rt_sigrestore_t;

#define _KNSIG		64
#define _NSIG_BPW	64

#define _KNSIG_WORDS	(_KNSIG / _NSIG_BPW)

typedef struct {
	unsigned long	sig[_KNSIG_WORDS];
} k_rtsigset_t;

/*
 * Used for rt_sigaction() system call - see kernel "struct sigaction" in
 * include/linux/signal.h.
 */
typedef struct {
	rt_sighandler_t	rt_sa_handler;
	unsigned long	rt_sa_flags;
	rt_sigrestore_t	rt_sa_restorer;
	k_rtsigset_t	rt_sa_mask;
} rt_sigaction_t;

struct mmap_arg_struct;

#endif /* COMPEL_ARCH_SYSCALL_TYPES_H__ */
