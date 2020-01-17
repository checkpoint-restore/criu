#ifndef __CR_ASM_RESTORER_H__
#define __CR_ASM_RESTORER_H__

#include <asm/ptrace.h>
#include <asm/elf.h>
#include <asm/types.h>
#include "asm/types.h"
#include <compel/asm/infect-types.h>

#include <compel/asm/sigframe.h>

/*
 * Clone trampoline
 *
 * See glibc sysdeps/powerpc/powerpc64/sysdep.h for FRAME_MIN_SIZE defines
 */
#define RUN_CLONE_RESTORE_FN(ret, clone_flags, new_sp, parent_tid, 	\
			     thread_args, clone_restore_fn)		\
	asm volatile( 							\
		"clone_emul:					\n"	\
		"/* Save fn, args, stack across syscall. */ 	\n"	\
		"mr	14, %5	/* clone_restore_fn in r14 */ 	\n"	\
		"mr	15, %6	/* &thread_args[i] in r15 */ 	\n"	\
		"mr	3, %1	/* clone_flags */ 		\n"	\
		"ld	4, %2	/* new_sp */ 			\n"	\
		"mr	5, %3	/* &parent_tid */ 		\n"	\
		"li	6, 0	/* tls = 0 ? */ 		\n"	\
		"mr	7, %4	/* &thread_args[i].pid */ 	\n"	\
		"li	0,"__stringify(__NR_clone)" 		\n"	\
		"sc 						\n"	\
		"/* Check for child process.  */		\n"	\
		"cmpdi   cr1,3,0 				\n"	\
		"crandc  cr1*4+eq,cr1*4+eq,cr0*4+so 		\n"	\
		"bne-    cr1,clone_end 				\n"	\
		"/* child */					\n"	\
		"addi 14, 14, 8 /* jump over r2 fixup */	\n"	\
		"mtctr	14					\n"	\
		"mr	3,15 					\n"	\
		"bctr 						\n"	\
		"clone_end:					\n"	\
		"mr	%0,3 \n"					\
		: "=r"(ret)			/* %0 */		\
		: "r"(clone_flags),		/* %1 */		\
		  "m"(new_sp),			/* %2 */		\
		  "r"(&parent_tid),		/* %3 */		\
		  "r"(&thread_args[i].pid),	/* %4 */		\
		  "r"(clone_restore_fn),	/* %5 */		\
		  "r"(&thread_args[i])		/* %6 */		\
		: "memory","0","3","4","5","6","7","14","15")

#define RUN_CLONE3_RESTORE_FN(ret, clone_args, size, args,		\
			      clone_restore_fn)				\
/*
 * The clone3() function accepts following parameters:
 *   int clone3(struct clone_args *args, size_t size)
 *
 * Always consult the CLONE3 wrappers for other architectures
 * for additional details.
 *
 * For PPC64LE the first parameter (clone_args) is passed in r3 and
 * the second parameter (size) is passed in r4.
 *
 * This clone3() wrapper is based on the clone() wrapper from above.
 */									\
	asm volatile(							\
		"clone3_emul:					\n"	\
		"/* Save fn, args across syscall. */		\n"	\
		"mr	14, %3	/* clone_restore_fn in r14 */	\n"	\
		"mr	15, %4	/* &thread_args[i] in r15 */	\n"	\
		"mr	3, %1	/* clone_args */		\n"	\
		"mr	4, %2	/* size */			\n"	\
		"li	0,"__stringify(__NR_clone3)"		\n"	\
		"sc						\n"	\
		"/* Check for child process. */			\n"	\
		"cmpdi	cr1,3,0					\n"	\
		"crandc	cr1*4+eq,cr1*4+eq,cr0*4+so		\n"	\
		"bne-	cr1,clone3_end				\n"	\
		"/* child */					\n"	\
		"addi	14, 14, 8 /* jump over r2 fixup */	\n"	\
		"mtctr	14					\n"	\
		"mr	3,15					\n"	\
		"bctr						\n"	\
		"clone3_end:					\n"	\
		"mr	%0,3					\n"	\
		: "=r"(ret)			/* %0 */		\
		: "r"(&clone_args),		/* %1 */		\
		  "r"(size),			/* %2 */		\
		  "r"(clone_restore_fn),	/* %3 */		\
		  "r"(args)			/* %4 */		\
		: "memory","0","3","4","5","14","15")

#define arch_map_vdso(map, compat)		-1

int restore_gpregs(struct rt_sigframe *f, UserPpc64RegsEntry *r);
int restore_nonsigframe_gpregs(UserPpc64RegsEntry *r);

/* Nothing to do, TLS is accessed through r13 */
static inline void restore_tls(tls_t *ptls) { (void)ptls; }

/*
 * Defined in arch/ppc64/syscall-common-ppc64.S
 */
unsigned long sys_shmat(int shmid, const void *shmaddr, int shmflg);

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
