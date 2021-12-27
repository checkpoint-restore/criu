/**
 * This source contains emulation of syscalls
 * that are not implemented in the riscv64 Linux kernel
 */

ENTRY(sys_open)
	mov a3, a2
	mov a2, a1
	mov a1, a0
	mov a0, #-100
	b   sys_openat
END(sys_open)


ENTRY(sys_mkdir)
	mov a3, a2
	mov a2, a1
	mov a1, a0
	mov a0, #-100
	b   sys_mkdirat
END(sys_mkdir)


ENTRY(sys_rmdir)
	mov a2, #0x200		// flags = AT_REMOVEDIR
	mov a1, a0
	mov a0, #-100
	b   sys_unlinkat
END(sys_rmdir)


ENTRY(sys_unlink)
	mov a2, #0		// flags = 0
	mov a1, a0
	mov a0, #-100
	b   sys_unlinkat
END(sys_unlink)
