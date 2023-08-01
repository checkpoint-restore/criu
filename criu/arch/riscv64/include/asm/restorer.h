#ifndef __CR_ASM_RESTORER_H__
#define __CR_ASM_RESTORER_H__

#include <sys/ucontext.h>

#include "asm/types.h"
#include "images/core.pb-c.h"

#include <compel/asm/sigframe.h>

// kernel arg order for clone
// unsigned long clone_flags,
// unsigned long newsp,
// int __user * parent_tidptr,
// unsigned long tls,
// int __user * child_tidptr
/* clang-format off */
#define RUN_CLONE_RESTORE_FN(ret, clone_flags, new_sp, parent_tid,		\
			     thread_args, clone_restore_fn)			\
	asm volatile(								\
			"clone_emul:					\n"	\
			"ld a1, %2					\n"	\
			"andi a1, a1, ~15				\n"	\
			"addi a1, a1, -16				\n"	\
			"sd %5, 0(a1)					\n"	\
			"sd %6, 8(a1)					\n"	\
			"mv a0, %1					\n"	\
			"mv a2, %3					\n"	\
			"mv a3, %4					\n"	\
			"li a7, "__stringify(__NR_clone)"		\n"	\
			"ecall						\n"	\
										\
			"beqz a0, thread_run				\n"	\
										\
			"mv %0, a0					\n"	\
			"j   clone_end					\n"	\
										\
			"thread_run:					\n"	\
			"ld a1, 0(sp)					\n"	\
			"ld a0, 8(sp)					\n"	\
			"jr  a1						\n"	\
										\
			"clone_end:					\n"	\
			: "=r"(ret)						\
			: "r"(clone_flags),					\
			  "m"(new_sp),						\
			  "r"(&parent_tid),					\
			  "r"(&thread_args[i].pid),				\
			  "r"(clone_restore_fn),				\
			  "r"(&thread_args[i])					\
			: "a0", "a1", "a2", "a3", "a7", "memory")

/*
 * Based on sysdeps/unix/sysv/linux/riscv/clone.S
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
	 * sysdeps/unix/sysv/linux/riscv/clone.S.
	 */									\
			"clone3_emul:					\n"	\
	/*
	 * Based on the glibc clone() wrapper, which uses x10 and x11
	 * to save the arguments for the child process, this does the same.
	 * x10 for the thread function and x11 for the thread arguments.
	 */									\
			"mv t0, %3	/* clone_restore_fn */		\n"	\
			"mv t1, %4	/* args */			\n"	\
			"mv a0, %1	/* &clone_args */		\n"	\
			"mv a1, %2	/* size */			\n"	\
	/* Load syscall number */						\
			"li a7, "__stringify(__NR_clone3)"		\n"	\
	/* Do the syscall */							\
			"ecall						\n"	\
										\
			"beqz a0, clone3_thread_run			\n"	\
										\
			"mv %0, a0					\n"	\
			"j   clone3_end					\n"	\
										\
			"clone3_thread_run:				\n"	\
	/* Move args to a0 */							\
			"mv a0, t1					\n"	\
	/* Jump to clone_restore_fn */						\
			"jr  t0						\n"	\
										\
			"clone3_end:					\n"	\
			: "=r"(ret)						\
			: "r"(&clone_args),					\
			  "r"(size),						\
			  "r"(clone_restore_fn),				\
			  "r"(args)						\
			: "a0", "a1", "a7", "t0", "t1", "memory")

#define ARCH_FAIL_CORE_RESTORE					\
	asm volatile(						\
			"mv sp, %0			\n"	\
			"li a0, 0			\n"	\
			"jr   x0			\n"	\
			:					\
			: "r"(ret)				\
			: "sp", "a0", "memory")
/* clang-format on */

#define arch_map_vdso(map, compat) -1

int restore_gpregs(struct rt_sigframe *f, UserRiscv64RegsEntry *r);
int restore_nonsigframe_gpregs(UserRiscv64RegsEntry *r);

static inline void restore_tls(tls_t *ptls)
{
	asm("mv tp, %0" : : "r"(*ptls));
}

static inline void *alloc_compat_syscall_stack(void)
{
	return NULL;
}
static inline void free_compat_syscall_stack(void *stack32)
{
}
static inline int arch_compat_rt_sigaction(void *stack, int sig, void *act)
{
	return -1;
}
static inline int set_compat_robust_list(uint32_t head_ptr, uint32_t len)
{
	return -1;
}

#endif