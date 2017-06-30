#include "asm/infect-types.h"

/*
 * Define prototype because of compile error if we include uapi/std/syscall.h
 */
long sys_old_mmap (struct mmap_arg_struct *);

/*
 * On s390 we have defined __ARCH_WANT_SYS_OLD_MMAP - Therefore implement
 * system call with one parameter "mmap_arg_struct".
 */
unsigned long sys_mmap(void *addr, unsigned long len, unsigned long prot,
		       unsigned long flags, unsigned long fd,
		       unsigned long offset)
{
	struct mmap_arg_struct arg_struct;

	arg_struct.addr = (unsigned long)addr;
	arg_struct.len = len;
	arg_struct.prot = prot;
	arg_struct.flags = flags;
	arg_struct.fd = fd;
	arg_struct.offset = offset;

	return sys_old_mmap(&arg_struct);
}
