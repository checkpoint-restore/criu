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

#define RUN_CLONE3_RESTORE_FN(ret, clone_args, size, args, \
			      clone_restore_fn)				\
	asm volatile(							\
	/*
	 * clone3 only needs two arguments (r2, r3), this means
	 * we can use r4 and r5 for args and thread function.
	 * r4 and r5 are callee-saved and are not overwritten.
	 * No need to put these values on the child stack.
	 */								\
	"lgr	%%r4,%4\n"	/* Save args in %r4 */			\
	"lgr	%%r5,%3\n"	/* Save clone_restore_fn in %r5 */	\
	"lgr	%%r2,%1\n"	/* Parameter 1: clone_args */		\
	"lgr	%%r3,%2\n"	/* Parameter 2: size */			\
	/*
	 * On s390x a syscall is done sc <syscall number>.
	 * That only works for syscalls < 255. clone3 is 435,
	 * therefore it is necessary to load the syscall number
	 * into r1 and do 'svc 0'.
	 */								\
	"lghi	%%r1,"__stringify(__NR_clone3)"\n"			\
	"svc	0\n"							\
	"ltgr	%0,%%r2\n"	/* Set and check "ret" */		\
	"jnz	0f\n"		/* ret != 0: Continue caller */		\
	"lgr	%%r2,%%r4\n"	/* Thread arguments taken from r4. */	\
	"lgr	%%r1,%%r5\n"	/* Thread function taken from r5. */	\
	"aghi	%%r15,-160\n"	/* Prepare stack frame */		\
	"xc	0(8,%%r15),0(%%r15)\n"					\
	"basr	%%r14,%%r1\n"	/* Jump to clone_restore_fn() */	\
	"j	.+2\n"		/* BUG(): Force PGM check */		\
"0:\n"				/* Continue caller */			\
	: "=d"(ret)							\
	: "a"(&clone_args),						\
	  "d"(size),							\
	  "d"(clone_restore_fn),					\
	  "d"(args)							\
	: "0", "1", "2", "3", "4", "5", "cc", "memory")

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
