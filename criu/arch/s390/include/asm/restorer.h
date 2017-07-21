#ifndef __CR_ASM_RESTORER_H__
#define __CR_ASM_RESTORER_H__

#include <asm/ptrace.h>
#include <asm/types.h>

#include "asm/types.h"

#include "sigframe.h"

/*
 * Clone trampoline - see glibc sysdeps/unix/sysv/linux/s390/s390-64/clone.S
 */
#define RUN_CLONE_RESTORE_FN(ret, clone_flags, new_sp, parent_tid,	\
			     thread_args, clone_restore_fn)		\
	asm volatile(							\
	"lgr	%%r0,%6\n"	/* Save thread_args in %r0 */		\
	"lgr	%%r1,%5\n"	/* Save clone_restore_fn in %r1 */	\
	"lgr	%%r2,%2\n"	/* Parm 1: new_sp (child stack) */	\
	"lgr	%%r3,%1\n"	/* Parm 2: clone_flags */		\
	"lgr	%%r4,%3\n"	/* Parm 3: &parent_tid */		\
	"lgr	%%r5,%4\n"	/* Parm 4: &thread_args[i].pid */	\
	"lghi	%%r6,0\n"	/* Parm 5: tls = 0 */			\
	"svc	"__stringify(__NR_clone)"\n"				\
	"ltgr	%0,%%r2\n"	/* Set and check "ret" */		\
	"jnz	0f\n"		/* ret != 0: Continue caller */		\
	"lgr	%%r2,%%r0\n"	/* Parm 1: &thread_args */		\
	"aghi	%%r15,-160\n"	/* Prepare stack frame */		\
	"xc	0(8,%%r15),0(%%r15)\n"					\
	"basr	%%r14,%%r1\n"	/* Jump to clone_restore_fn() */	\
	"j	.+2\n"		/* BUG(): Force PGM check */		\
"0:\n"				/* Continue caller */			\
	: "=d"(ret)							\
	: "d"(clone_flags),						\
	  "a"(new_sp),							\
	  "d"(&parent_tid),						\
	  "d"(&thread_args[i].pid),					\
	  "d"(clone_restore_fn),					\
	  "d"(&thread_args[i])						\
	: "0", "1", "2", "3", "4", "5", "6", "cc", "memory")

#define kdat_compatible_cr()			0
#define kdat_can_map_vdso()			0
#define arch_map_vdso(map, compat)		-1

int restore_gpregs(struct rt_sigframe *f, UserS390RegsEntry *r);
int restore_nonsigframe_gpregs(UserS390RegsEntry *r);

unsigned long sys_shmat(int shmid, const void *shmaddr, int shmflg);
unsigned long sys_mmap(void *addr, unsigned long len, unsigned long prot,
		       unsigned long flags, unsigned long fd,
		       unsigned long offset);

static inline void restore_tls(tls_t *ptls) { (void)ptls; }
static inline void *alloc_compat_syscall_stack(void) { return NULL; }
static inline void free_compat_syscall_stack(void *stack32) { }
static inline int arch_compat_rt_sigaction(void *stack, int sig, void *act)
{
	return -1;
}

static inline int set_compat_robust_list(uint32_t head_ptr, uint32_t len)
{
	return -1;
}

#endif /*__CR_ASM_RESTORER_H__*/
