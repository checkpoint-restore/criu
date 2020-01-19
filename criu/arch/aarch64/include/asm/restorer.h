#ifndef __CR_ASM_RESTORER_H__
#define __CR_ASM_RESTORER_H__

#include <asm/sigcontext.h>
#include <sys/ucontext.h>

#include "asm/types.h"
#include "images/core.pb-c.h"

#include <compel/asm/sigframe.h>

#define RUN_CLONE_RESTORE_FN(ret, clone_flags, new_sp, parent_tid,		\
			     thread_args, clone_restore_fn)			\
	asm volatile(								\
			"clone_emul:					\n"	\
			"ldr x1, %2					\n"	\
			"and x1, x1, #~15				\n"	\
			"sub x1, x1, #16				\n"	\
			"stp %5, %6, [x1]				\n"	\
			"mov x0, %1					\n"	\
			"mov x2, %3					\n"	\
			"mov x3, %4					\n"	\
			"mov x8, #"__stringify(__NR_clone)"		\n"	\
			"svc #0						\n"	\
										\
			"cbz x0, thread_run				\n"	\
										\
			"mov %0, x0					\n"	\
			"b   clone_end					\n"	\
										\
			"thread_run:					\n"	\
			"ldp x1, x0, [sp]				\n"	\
			"br  x1						\n"	\
										\
			"clone_end:					\n"	\
			: "=r"(ret)						\
			: "r"(clone_flags),					\
			  "m"(new_sp),						\
			  "r"(&parent_tid),					\
			  "r"(&thread_args[i].pid),				\
			  "r"(clone_restore_fn),				\
			  "r"(&thread_args[i])					\
			: "x0", "x1", "x2", "x3", "x8", "memory")

/*
 * Based on sysdeps/unix/sysv/linux/aarch64/clone.S
 *
 * int clone(int (*fn)(void *arg),            x0
 *	     void *child_stack,               x1
 *	     int flags,                       x2
 *	     void *arg,                       x3
 *	     pid_t *ptid,                     x4
 *	     struct user_desc *tls,           x5
 *	     pid_t *ctid);                    x6
 *
 * int clone3(struct clone_args *args,        x0
 *	      size_t size);                   x1
 *
 * Always consult the CLONE3 wrappers for other architectures
 * for additional details.
 *
 */

#define RUN_CLONE3_RESTORE_FN(ret, clone_args, size, args,			\
			      clone_restore_fn)					\
	asm volatile(								\
	/* In contrast to the clone() wrapper above this does not put
	 * the thread function and its arguments on the child stack,
	 * but uses registers to pass these parameters to the child process.
	 * Based on the glibc clone() wrapper at
	 * sysdeps/unix/sysv/linux/aarch64/clone.S.
	 */									\
			"clone3_emul:					\n"	\
	/*
	 * Based on the glibc clone() wrapper, which uses x10 and x11
	 * to save the arguments for the child process, this does the same.
	 * x10 for the thread function and x11 for the thread arguments.
	 */									\
			"mov x10, %3	/* clone_restore_fn */		\n"	\
			"mov x11, %4	/* args */			\n"	\
			"mov x0, %1	/* &clone_args */		\n"	\
			"mov x1, %2	/* size */			\n"	\
	/* Load syscall number */						\
			"mov x8, #"__stringify(__NR_clone3)"		\n"	\
	/* Do the syscall */							\
			"svc #0						\n"	\
										\
			"cbz x0, clone3_thread_run			\n"	\
										\
			"mov %0, x0					\n"	\
			"b   clone3_end					\n"	\
										\
			"clone3_thread_run:				\n"	\
	/* Move args to x0 */							\
			"mov x0, x11					\n"	\
	/* Jump to clone_restore_fn */						\
			"br  x10					\n"	\
										\
			"clone3_end:					\n"	\
			: "=r"(ret)						\
			: "r"(&clone_args),					\
			  "r"(size),						\
			  "r"(clone_restore_fn),				\
			  "r"(args)						\
			: "x0", "x1", "x8", "x10", "x11", "memory")

#define ARCH_FAIL_CORE_RESTORE					\
	asm volatile(						\
			"mov sp, %0			\n"	\
			"mov x0, #0			\n"	\
			"b   x0				\n"	\
			:					\
			: "r"(ret)				\
			: "sp", "x0", "memory")


#define arch_map_vdso(map, compat)		-1

int restore_gpregs(struct rt_sigframe *f, UserAarch64RegsEntry *r);
int restore_nonsigframe_gpregs(UserAarch64RegsEntry *r);

static inline void restore_tls(tls_t *ptls)
{
	asm("msr tpidr_el0, %0" : : "r" (*ptls));
}

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

#endif
