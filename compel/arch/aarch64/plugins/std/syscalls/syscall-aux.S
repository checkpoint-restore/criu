/**
 * This source contains emulation of syscalls
 * that are not implemented in the AArch64 Linux kernel
 */

ENTRY(sys_open)
	mov x3, x2
	mov x2, x1
	mov x1, x0
	mov x0, #-100
	b   sys_openat
END(sys_open)


ENTRY(sys_mkdir)
	mov x3, x2
	mov x2, x1
	mov x1, x0
	mov x0, #-100
	b   sys_mkdirat
END(sys_mkdir)


ENTRY(sys_rmdir)
	mov x2, #0x200		// flags = AT_REMOVEDIR
	mov x1, x0
	mov x0, #-100
	b   sys_unlinkat
END(sys_rmdir)


ENTRY(sys_unlink)
	mov x2, #0		// flags = 0
	mov x1, x0
	mov x0, #-100
	b   sys_unlinkat
END(sys_unlink)
