#ifndef __CR_ASM_RESTORER_H__
#define __CR_ASM_RESTORER_H__

#include "asm/types.h"
#include "images/core.pb-c.h"

#include <compel/asm/sigframe.h>

/* clang-format off */
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


/*
 * The clone3() assembler wrapper is based on the clone() wrapper above
 * and on code from the glibc wrapper at
 * sysdeps/unix/sysv/linux/arm/clone.S
 *
 * For arm it is necessary to change the child stack as on x86_64 as
 * it seems there are not registers which stay the same over a syscall
 * like on s390x, ppc64le and aarch64.
 *
 * Changing the child stack means that this code has to deal with the
 * kernel doing stack + stack_size implicitly.
 *
 * int clone3(struct clone_args *args, size_t size)
 */

#define RUN_CLONE3_RESTORE_FN(ret, clone_args, size, args,		\
			      clone_restore_fn)				\
	asm volatile(							\
		"clone3_emul:					\n"	\
	/* Load thread stack pointer */					\
		"ldr r1, [%3]					\n"	\
	/* Load thread stack size */					\
		"mov r2, %4					\n"	\
	/* Goto to the end of stack */					\
		"add r1, r1, r2					\n"	\
	/* Load thread function and arguments and push on stack */	\
		"mov r2, %6		/* args */		\n"	\
		"str r2, [r1, #4]	/* args */		\n"	\
		"mov r2, %5		/* function */		\n"	\
		"str r2, [r1]		/* function */		\n"	\
		"mov r0, %1		/* clone_args */	\n"	\
		"mov r1, %2		/* size */		\n"	\
		"mov r7, #"__stringify(__NR_clone3)"		\n"	\
		"svc #0						\n"	\
									\
		"cmp r0, #0					\n"	\
		"beq thread3_run				\n"	\
									\
		"mov %0, r0					\n"	\
		"b   clone3_end					\n"	\
									\
		"thread3_run:					\n"	\
		"pop { r1 }					\n"	\
		"pop { r0 }					\n"	\
		"bx  r1						\n"	\
									\
		"clone3_end:					\n"	\
			: "=r"(ret)					\
			: "r"(&clone_args),				\
			  "r"(size),					\
			  "r"(&clone_args.stack),			\
			  "r"(clone_args.stack_size),			\
			  "r"(clone_restore_fn),			\
			  "r"(args)					\
			: "r0", "r1", "r2", "r7", "memory")

#define ARCH_FAIL_CORE_RESTORE					\
	asm volatile(						\
		     "mov sp, %0			\n"	\
		     "mov r0, #0			\n"	\
		     "bx  r0				\n"	\
		     :						\
		     : "r"(ret)					\
		     : "memory")
/* clang-format on */

#define arch_map_vdso(map, compat) -1

int restore_gpregs(struct rt_sigframe *f, UserArmRegsEntry *r);
int restore_nonsigframe_gpregs(UserArmRegsEntry *r);
#define ARCH_HAS_SHMAT_HOOK
unsigned long arch_shmat(int shmid, void *shmaddr, int shmflg, unsigned long size);

static inline void restore_tls(tls_t *ptls)
{
	asm("mov r7, #15	\n"
	    "lsl r7, #16	\n"
	    "mov r0, #5	\n"
	    "add r7, r0	\n" /* r7 = 0xF005 */
	    "ldr r0, [%0]	\n"
	    "svc #0		\n"
	    :
	    : "r"(ptls)
	    : "r0", "r7");
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
