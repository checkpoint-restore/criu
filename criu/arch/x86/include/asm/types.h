#ifndef __CR_ASM_TYPES_H__
#define __CR_ASM_TYPES_H__

#include <stdbool.h>
#include <signal.h>

#include "page.h"
#include "bitops.h"
#include "asm/int.h"

#include "images/core.pb-c.h"

#ifdef CONFIG_X86_64
static inline int core_is_compat(CoreEntry *c)
{
	switch (c->thread_info->gpregs->mode) {
		case USER_X86_REGS_MODE__NATIVE:
			return 0;
		case USER_X86_REGS_MODE__COMPAT:
			return 1;
		default:
			return -1;
	}
}
#else /* CONFIG_X86_64 */
static inline int core_is_compat(CoreEntry *c) { return 0; }
#endif /* CONFIG_X86_64 */

typedef void rt_signalfn_t(int, siginfo_t *, void *);
typedef rt_signalfn_t *rt_sighandler_t;

typedef void rt_restorefn_t(void);
typedef rt_restorefn_t *rt_sigrestore_t;

#define _KNSIG           64
# define _NSIG_BPW      64

#define _KNSIG_WORDS     (_KNSIG / _NSIG_BPW)

typedef struct {
	u64 sig[_KNSIG_WORDS];
} k_rtsigset_t;

#define SA_RESTORER	0x04000000

typedef struct {
	rt_sighandler_t	rt_sa_handler;
	unsigned long	rt_sa_flags;
	rt_sigrestore_t	rt_sa_restorer;
	k_rtsigset_t	rt_sa_mask;
} rt_sigaction_t;

/*
 * Note: there is unaligned access on x86_64 and it's fine.
 * However, when porting this code -- keep in mind about possible issues
 * with unaligned rt_sa_mask.
 */
typedef struct __attribute__((packed)) {
	u32	rt_sa_handler;
	u32	rt_sa_flags;
	u32	rt_sa_restorer;
	k_rtsigset_t	rt_sa_mask;
} rt_sigaction_t_compat;

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

#define CORE_ENTRY__MARCH CORE_ENTRY__MARCH__X86_64

#define CORE_THREAD_ARCH_INFO(core) core->thread_info

typedef UserX86RegsEntry UserRegsEntry;

static inline u64 encode_pointer(void *p) { return (u64)(long)p; }
static inline void *decode_pointer(u64 v) { return (void*)(long)v; }

#endif /* __CR_ASM_TYPES_H__ */
