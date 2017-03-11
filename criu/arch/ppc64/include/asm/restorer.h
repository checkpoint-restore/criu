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

#define kdat_compat_sigreturn_test()			0

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
static inline int
arch_compat_rt_sigaction(void *stack, int sig, void *act) { return -1; }

#endif /*__CR_ASM_RESTORER_H__*/
