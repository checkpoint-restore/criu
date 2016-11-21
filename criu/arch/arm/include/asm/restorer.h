#ifndef __CR_ASM_RESTORER_H__
#define __CR_ASM_RESTORER_H__

#include "asm/types.h"
#include "images/core.pb-c.h"

#include "sigframe.h"

#define RUN_CLONE_RESTORE_FN(ret, clone_flags, new_sp, parent_tid,	\
			     thread_args, clone_restore_fn)		\
	asm volatile(							\
		     "clone_emul:				\n"	\
		     "ldr r1, %2				\n"	\
		     "sub r1, #16				\n"	\
		     "mov r0, %6				\n"	\
		     "str r0, [r1, #4]				\n"	\
		     "mov r0, %5				\n"	\
		     "str r0, [r1]				\n"	\
		     "mov r0, %1				\n"	\
		     "mov r2, %3				\n"	\
		     "mov r3, %4				\n"	\
		     "mov r7, #"__stringify(__NR_clone)"	\n"	\
		     "svc #0					\n"	\
									\
		     "cmp r0, #0				\n"	\
		     "beq thread_run				\n"	\
									\
		     "mov %0, r0				\n"	\
		     "b   clone_end				\n"	\
									\
		     "thread_run:				\n"	\
		     "pop { r1 }				\n"	\
		     "pop { r0 }				\n"	\
		     "bx  r1					\n"	\
									\
		     "clone_end:				\n"	\
		     : "=r"(ret)					\
		     : "r"(clone_flags),				\
		       "m"(new_sp),					\
		       "r"(&parent_tid),				\
		       "r"(&thread_args[i].pid),			\
		       "r"(clone_restore_fn),				\
		       "r"(&thread_args[i])				\
		     : "r0", "r1", "r2", "r3", "r7", "memory")

#define ARCH_FAIL_CORE_RESTORE					\
	asm volatile(						\
		     "mov sp, %0			\n"	\
		     "mov r0, #0			\n"	\
		     "bx  r0				\n"	\
		     :						\
		     : "r"(ret)					\
		     : "memory")




int restore_gpregs(struct rt_sigframe *f, UserArmRegsEntry *r);
int restore_nonsigframe_gpregs(UserArmRegsEntry *r);

static inline void restore_tls(tls_t *ptls) {
	asm (
	     "mov r7, #15	\n"
	     "lsl r7, #16	\n"
	     "mov r0, #5	\n"
	     "add r7, r0	\n"	/* r7 = 0xF005 */
	     "ldr r0, [%0]	\n"
	     "svc #0		\n"
	     :
	     : "r"(ptls)
	     : "r0", "r7"
	     );
}

static inline int ptrace_set_breakpoint(pid_t pid, void *addr)
{
	return 0;
}

static inline int ptrace_flush_breakpoints(pid_t pid)
{
	return 0;
}

#endif
