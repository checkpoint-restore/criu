#include "asm/linkage.h"
#include <asm/unistd.h>		/* for __NR_ipc */

#define SYSCALL(name, opcode)		\
	ENTRY(name);			\
	li	r0, opcode;		\
	b	__syscall_common;	\
	END(name)

	.text
	.align	4

ENTRY(__syscall_common)
	sc
	bnslr+		/* if no error return to LR */
	neg	r3,r3	/* r3 = -r3 to return -errno value */
	blr
END(__syscall_common)

ENTRY(__cr_restore_rt)
	li	r0, __NR_rt_sigreturn
	b	__syscall_common
END(__cr_restore_rt)

# On Power, shmat is done through the ipc system call.
ENTRY(sys_shmat)
	mr	r7, r4	# shmaddr -> ptr
	mr	r4, r3	# shmid -> first
	li	r3, 21	# call = SHMAT
	li	r0, __NR_ipc
	b	__syscall_common
END(sys_shmat)
