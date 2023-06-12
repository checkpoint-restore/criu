#ifndef __CR_ASM_RESTORER_H__
#define __CR_ASM_RESTORER_H__

#include "asm/types.h"
#include <compel/asm/fpu.h>
#include "images/core.pb-c.h"
#include <compel/plugins/std/syscall-codes.h>
#include <compel/asm/sigframe.h>

/* clang-format off */
#define RUN_CLONE_RESTORE_FN(ret, clone_flags, new_sp, parent_tid,	\
			thread_args, clone_restore_fn)			\
		asm volatile(								\
				"clone_emul:					\n"	\
				"ld.d		$a1, %2				\n"	\
				"addi.d		$a1, $a1, -16 		\n"	\
				"st.d		%5, $a1, 0			\n"	\
				"st.d		%6, $a1, 8			\n"	\
				"or			$a0, $zero, %1		\n"	\
				"or			$a2, $zero, %3		\n"	\
				"or			$a3, $zero, %4		\n"	\
				"ori 		$a7, $zero, "__stringify(__NR_clone)"	\n"	\
				"syscall	0					\n"	\
												   	\
				"beqz		$a0, thread_run     \n"	\
												   	\
				"or			%0, $zero, $a0		\n"	\
				"b			clone_end			\n"	\
												   	\
				"thread_run:					\n"	\
				"ld.d		$a1, $sp, 0			\n"	\
				"ld.d		$a0, $sp, 8			\n"	\
				"jirl		$ra, $a1, 0			\n"	\
												   	\
				"clone_end:						\n"	\
				: "=r"(ret)							\
				: "r"(clone_flags),					\
				  "ZB"(new_sp),						\
				  "r"(&parent_tid),					\
				  "r"(&thread_args[i].pid),			\
				  "r"(&clone_restore_fn),			\
				  "r"(&thread_args[i])				\
				: "$a0", "$a1", "$a2", "$a3", "$a7", "memory")

#define RUN_CLONE3_RESTORE_FN(ret, clone_args, size, args,	\
			clone_restore_fn)								\
		asm volatile(								\
				"clone3_emul:					\n"	\
				"or			$a0, $zero, %1		\n"	\
				"or			$a1, $zero, %2		\n"	\
				"or			$a2, $zero, %3		\n"	\
				"or			$a3, $zero, %4		\n"	\
				"ori		$a7, $zero, "__stringify(__NR_clone3)"	\n"	\
				"syscall	0					\n"	\
													\
				"beqz		$a0, clone3_thread_run	\n"	\
													\
				"or			%0, $zero, $a0		\n"	\
				"b			clone3_end			\n"	\
													\
				"clone3_thread_run:				\n"	\
				"or			$a0, $zero, $a3		\n"	\
				"jirl		$ra, $a2, 0			\n"	\
				"clone3_end:					\n"	\
				: "=r"(ret)							\
				: "r"(&clone_args),					\
				  "r"(size),						\
				  "r"(clone_restore_fn),			\
				  "r"(args)							\
				: "$a0", "$a1", "$a2", "$a3", "$a7", "memory")
/* clang-format on */

static inline void restore_tls(tls_t *ptls)
{
	asm volatile("or $tp, $zero, %0" : : "r"(*ptls));
}
static inline int arch_compat_rt_sigaction(void *stack, int sig, void *act)
{
	return -1;
}
static inline int set_compat_robust_list(uint32_t head_ptr, uint32_t len)
{
	return -1;
}
static inline void *alloc_compat_syscall_stack(void)
{
	return NULL;
}
static inline void free_compat_syscall_stack(void *stack32)
{
}
int restore_gpregs(struct rt_sigframe *f, UserLoongarch64GpregsEntry *r);
int restore_nonsigframe_gpregs(UserLoongarch64GpregsEntry *r);

#define arch_map_vdso(map, compat) -1

#endif
