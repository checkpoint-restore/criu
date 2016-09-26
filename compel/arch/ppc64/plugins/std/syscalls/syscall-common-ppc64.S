#include "common/asm/linkage.h"
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

