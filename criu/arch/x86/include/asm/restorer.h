#ifndef __CR_ASM_RESTORER_H__
#define __CR_ASM_RESTORER_H__

#include "asm/types.h"
#include "asm/fpu.h"
#include "images/core.pb-c.h"

#include "sigframe.h"

#ifdef CONFIG_X86_64
#define RUN_CLONE_RESTORE_FN(ret, clone_flags, new_sp, parent_tid,      \
			     thread_args, clone_restore_fn)             \
	asm volatile(							\
		     "clone_emul:				\n"	\
		     "movq %2, %%rsi				\n"	\
		     "subq $16, %%rsi			        \n"	\
		     "movq %6, %%rdi				\n"	\
		     "movq %%rdi, 8(%%rsi)			\n"	\
		     "movq %5, %%rdi				\n"	\
		     "movq %%rdi, 0(%%rsi)			\n"	\
		     "movq %1, %%rdi				\n"	\
		     "movq %3, %%rdx				\n"	\
		     "movq %4, %%r10				\n"	\
		     "movl $"__stringify(__NR_clone)", %%eax	\n"	\
		     "syscall				        \n"	\
									\
		     "testq %%rax,%%rax			        \n"	\
		     "jz thread_run				\n"	\
									\
		     "movq %%rax, %0				\n"	\
		     "jmp clone_end				\n"	\
									\
		     "thread_run:				\n"	\
		     "xorq %%rbp, %%rbp			        \n"	\
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

#define ARCH_FAIL_CORE_RESTORE					\
	asm volatile(						\
		     "movq %0, %%rsp			    \n"	\
		     "movq 0, %%rax			    \n"	\
		     "jmp *%%rax			    \n"	\
		     :						\
		     : "r"(ret)					\
		     : "memory")
#else /* CONFIG_X86_64 */
#define RUN_CLONE_RESTORE_FN(ret, clone_flags, new_sp, parent_tid,      \
			     thread_args, clone_restore_fn)             \
	(void)ret;							\
	(void)clone_flags;						\
	(void)new_sp;							\
	(void)parent_tid;						\
	(void)thread_args;						\
	(void)clone_restore_fn;						\
	;
#define ARCH_FAIL_CORE_RESTORE					\
	asm volatile(						\
		     "movl %0, %%esp			    \n"	\
		     "xorl %%eax, %%eax			    \n"	\
		     "jmp *%%eax			    \n"	\
		     :						\
		     : "r"(ret)					\
		     : "memory")
#endif /* CONFIG_X86_64 */

int restore_gpregs(struct rt_sigframe *f, UserX86RegsEntry *r);
int restore_nonsigframe_gpregs(UserX86RegsEntry *r);

static inline void restore_tls(tls_t *ptls) { (void)ptls; }

int ptrace_set_breakpoint(pid_t pid, void *addr);
int ptrace_flush_breakpoints(pid_t pid);


#endif
