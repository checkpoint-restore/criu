/**
 * This source contains emulation of syscalls
 * that are not implemented in the riscv64 Linux kernel
 */

ENTRY(sys_open)
	add a3, x0, a2
	add a2, x0, a1
	add a1, x0, a0
	addi a0, x0, -100
	j   sys_openat
END(sys_open)


ENTRY(sys_mkdir)
	add a3,x0, a2
	add a2, x0, a1
	add a1, x0, a0
	addi a0, x0, -100
	j   sys_mkdirat
END(sys_mkdir)


ENTRY(sys_rmdir)
	addi a2, x0, 0x200		// flags = AT_REMOVEDIR
	add a1, x0, a0
	addi a0, x0, -100
	j   sys_unlinkat
END(sys_rmdir)


ENTRY(sys_unlink)
	addi a2, x0, 0		// flags = 0
	add a1, x0, a0
	addi a0, x0, -100
	j   sys_unlinkat
END(sys_unlink)