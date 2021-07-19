#ifndef __CR_ASM_RESTORER_H__
#define __CR_ASM_RESTORER_H__

#include "asm/types.h"
#include <compel/asm/fpu.h>
#include <compel/asm/infect-types.h>
#include "images/core.pb-c.h"
#include <compel/plugins/std/syscall-codes.h>
#include <compel/asm/sigframe.h>
#include "asm/compat.h"

#ifdef CONFIG_COMPAT
extern void restore_tls(tls_t *ptls);
extern int arch_compat_rt_sigaction(void *stack32, int sig, rt_sigaction_t_compat *act);
extern int set_compat_robust_list(uint32_t head_ptr, uint32_t len);
#else /* CONFIG_COMPAT */
static inline void restore_tls(tls_t *ptls)
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
#endif /* !CONFIG_COMPAT */

/*
 * Documentation copied from glibc sysdeps/unix/sysv/linux/x86_64/clone.S
 * The kernel expects:
 * rax: system call number
 * rdi: flags
 * rsi: child_stack
 * rdx: TID field in parent
 * r10: TID field in child
 * r8:	thread pointer
 *
 * int clone(unsigned long clone_flags, unsigned long newsp,
 *           int *parent_tidptr, int *child_tidptr,
 *           unsigned long tls);
 */

/* clang-format off */
#define RUN_CLONE_RESTORE_FN(ret, clone_flags, new_sp, parent_tid,	\
			     thread_args, clone_restore_fn)		\
	asm volatile(							\
		     "clone_emul:				\n"	\
		     "movq %2, %%rsi				\n"	\
		     "subq $16, %%rsi				\n"	\
		     "movq %6, %%rdi				\n"	\
		     "movq %%rdi, 8(%%rsi)			\n"	\
		     "movq %5, %%rdi				\n"	\
		     "movq %%rdi, 0(%%rsi)			\n"	\
		     "movq %1, %%rdi				\n"	\
		     "movq %3, %%rdx				\n"	\
		     "movq %4, %%r10				\n"	\
		     "movl $"__stringify(__NR_clone)", %%eax	\n"	\
		     "syscall					\n"	\
									\
		     "testq %%rax,%%rax				\n"	\
		     "jz thread_run				\n"	\
									\
		     "movq %%rax, %0				\n"	\
		     "jmp clone_end				\n"	\
									\
		     "thread_run:				\n"	\
		     "xorq %%rbp, %%rbp				\n"	\
		     "popq %%rax				\n"	\
		     "popq %%rdi				\n"	\
		     "callq *%%rax				\n"	\
									\
		     "clone_end:				\n"	\
		     : "=r"(ret)					\
		     : "g"(clone_flags),				\
		       "g"(new_sp),					\
		       "g"(&parent_tid),				\
		       "g"(&thread_args[i].pid),			\
		       "g"(clone_restore_fn),				\
		       "g"(&thread_args[i])				\
		     : "rax", "rcx", "rdi", "rsi", "rdx", "r10", "r11", "memory")

/* int clone3(struct clone_args *args, size_t size) */
#define RUN_CLONE3_RESTORE_FN(ret, clone_args, size, args,		\
			      clone_restore_fn)				\
	asm volatile(							\
		     "clone3_emul:				\n"	\
	/*
	 * Prepare stack pointer for child process. The kernel does
	 * stack + stack_size before passing the stack pointer to the
	 * child process. As we have to put the function and the
	 * arguments for the new process on that stack we have handle
	 * the kernel's implicit stack + stack_size.
	 */								\
		     "movq (%3), %%rsi	/* new stack pointer */	\n"	\
	/* Move the stack_size to %rax to use later as the offset */	\
		     "movq %4, %%rax				\n"	\
	/* 16 bytes are needed on the stack for function and args */	\
		     "subq $16, (%%rsi, %%rax)			\n"	\
		     "movq %6, %%rdi	/* thread args */	\n"	\
		     "movq %%rdi, 8(%%rsi, %%rax)		\n"	\
		     "movq %5, %%rdi	/* thread function */	\n"	\
		     "movq %%rdi, 0(%%rsi, %%rax)		\n"	\
	/*
	 * The stack address has been modified for the two
	 * elements above (child function, child arguments).
	 * This modified stack needs to be stored back into the
	 * clone_args structure.
	 */								\
		     "movq (%%rsi), %3				\n"	\
	/*
	 * Do the actual clone3() syscall. First argument (%rdi) is
	 * the clone_args structure, second argument is the size
	 * of clone_args.
	 */								\
		     "movq %1, %%rdi	/* clone_args */	\n"	\
		     "movq %2, %%rsi	/* size */		\n"	\
		     "movl $"__stringify(__NR_clone3)", %%eax	\n"	\
		     "syscall					\n"	\
	/*
	 * If clone3() was successful and if we are in the child
	 * '0' is returned. Jump to the child function handler.
	 */								\
		     "testq %%rax,%%rax				\n"	\
		     "jz thread3_run				\n"	\
	/* Return the PID to the parent process. */			\
		     "movq %%rax, %0				\n"	\
		     "jmp clone3_end				\n"	\
									\
		     "thread3_run:	/* Child process */	\n"	\
	/* Clear the frame pointer */					\
		     "xorq %%rbp, %%rbp				\n"	\
	/* Pop the child function from the stack */			\
		     "popq %%rax				\n"	\
	/* Pop the child function arguments from the stack */		\
		     "popq %%rdi				\n"	\
	/* Run the child function */					\
		     "callq *%%rax				\n"	\
	/*
	 * If the child function is expected to return, this
	 * would be the place to handle the return code. In CRIU's
	 * case the child function is expected to not return
	 * and do exit() itself.
	 */								\
									\
		     "clone3_end:				\n"	\
		     : "=r"(ret)					\
	/*
	 * This uses the "r" modifier for all parameters
	 * as clang complained if using "g".
	 */								\
		     : "r"(&clone_args),				\
		       "r"(size),					\
		       "r"(&clone_args.stack),				\
		       "r"(clone_args.stack_size),			\
		       "r"(clone_restore_fn),				\
		       "r"(args)					\
		     : "rax", "rcx", "rdi", "rsi", "rdx", "r10", "r11", "memory")

#define ARCH_FAIL_CORE_RESTORE					\
	asm volatile(						\
		     "movq %0, %%rsp			    \n"	\
		     "movq 0, %%rax			    \n"	\
		     "jmp *%%rax			    \n"	\
		     :						\
		     : "r"(ret)					\
		     : "memory")
/* clang-format on */

static inline void __setup_sas_compat(struct ucontext_ia32 *uc, ThreadSasEntry *sas)
{
	uc->uc_stack.ss_sp = (compat_uptr_t)(sas)->ss_sp;
	uc->uc_stack.ss_flags = (int)(sas)->ss_flags;
	uc->uc_stack.ss_size = (compat_size_t)(sas)->ss_size;
}

static inline void __setup_sas(struct rt_sigframe *sigframe, ThreadSasEntry *sas)
{
	if (sigframe->is_native) {
		struct rt_ucontext *uc = &sigframe->native.uc;

		uc->uc_stack.ss_sp = (void *)decode_pointer((sas)->ss_sp);
		uc->uc_stack.ss_flags = (int)(sas)->ss_flags;
		uc->uc_stack.ss_size = (size_t)(sas)->ss_size;
	} else {
		__setup_sas_compat(&sigframe->compat.uc, sas);
	}
}

static inline void _setup_sas(struct rt_sigframe *sigframe, ThreadSasEntry *sas)
{
	if (sas)
		__setup_sas(sigframe, sas);
}
#define setup_sas _setup_sas

int restore_gpregs(struct rt_sigframe *f, UserX86RegsEntry *r);
int restore_nonsigframe_gpregs(UserX86RegsEntry *r);

int ptrace_set_breakpoint(pid_t pid, void *addr);
int ptrace_flush_breakpoints(pid_t pid);

extern int arch_map_vdso(unsigned long map_at, bool compatible);

#endif
