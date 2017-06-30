#include "common/asm/linkage.h"

/*
 * Define a system call
 *
 * C-ABI on s390:
 * - Parameters 1-5 are passed in %r2-%r6
 * - Parameter 6 is passed on the stack 160(%r15)
 * - Return value is in %r2
 * - Return address is in %r14
 * - Registers %r0-%r6,%r14 are call-clobbered
 * - Registers %r7-%r13,%r15 are call-saved
 *
 * SVC ABI on s390:
 * - For SVC 0 the system call number is passed in %r1
 * - Parameters 1-6 are passed in %r2-%r7
 * - Return value is passed in %r2
 * - Besides of %r2 all registers are call-saved
 */
#define SYSCALL(name, opcode)						\
ENTRY(name);								\
	lgr	%r0,%r7;		/* Save %r7 */			\
	lg	%r7,160(%r15);		/* Load 6th parameter */	\
	lghi	%r1,opcode;		/* Load SVC number */		\
	svc	0;			/* Issue SVC 0 */		\
	lgr	%r7,%r0;		/* Restore %r7 */		\
	br	%r14;			/* Return to caller */		\
END(name)								\

/*
 * Issue rt_sigreturn system call for sa_restorer
 */
ENTRY(__cr_restore_rt)
	lghi	%r1,__NR_rt_sigreturn
	svc	0
END(__cr_restore_rt)

