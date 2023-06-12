#include "common/asm/linkage.h"

#define SYSCALL(name, opcode)		\
ENTRY(name);					\
	addi.d	$a7, $zero, opcode;	\
	syscall 0;					\
	jirl	$r0, $r1, 0;		\
END(name)

#ifndef AT_FDCWD
#define AT_FDCWD	-100
#endif

#ifndef AT_REMOVEDIR
#define AT_REMOVEDIR	0x200
#endif

ENTRY(sys_open)
	or		$a3, $zero, $a2
	or		$a2, $zero, $a1
	or		$a1, $zero, $a0
	addi.d	$a0, $zero, AT_FDCWD
	b		sys_openat
END(sys_open)

ENTRY(sys_mkdir)
	or		$a3, $zero, $a2
	or		$a2, $zero, $a1
	or		$a1, $zero, $a0
	addi.d	$a0, $zero, AT_FDCWD
	b		sys_mkdirat
END(sys_mkdir)

ENTRY(sys_rmdir)
	addi.d	$a2, $zero, AT_REMOVEDIR
	or		$a1, $zero, $a0
	addi.d	$a0, $zero, AT_FDCWD
	b		sys_unlinkat
END(sys_rmdir)

ENTRY(__cr_restore_rt)
	addi.d	$a7, $zero, __NR_rt_sigreturn
	syscall	0
END(__cr_restore_rt)
