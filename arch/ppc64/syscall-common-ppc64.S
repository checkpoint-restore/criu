#include "asm/linkage.h"
#include <asm/unistd.h>		/* for __NR_ipc */

#define SYSCALL(name, opcode)		\
	ENTRY(name);			\
	li	0, opcode;		\
	b	__syscall_common;	\
	END(name)

	.text
	.align	4

ENTRY(__syscall_common)
	sc
	bnslr+		/* if no error return to LR */
	neg	3,3	/* r3 = -r3 to return -errno value */
	blr
END(__syscall_common)

ENTRY(__cr_restore_rt)
	li	0, __NR_rt_sigreturn
	b	__syscall_common
END(__cr_restore_rt)

	# On Power, shmat is done through the ipc system call.
ENTRY(sys_shmat)
	mr	7, 4	# shmaddr -> ptr
	mr	4, 3	# shmid -> first
	li	3, 21	# call = SHMAT
	li	0, __NR_ipc
	b	__syscall_common
END(sys_shmat)
