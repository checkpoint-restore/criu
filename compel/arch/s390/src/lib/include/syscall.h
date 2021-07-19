#ifndef __COMPEL_SYSCALL_H__
#define __COMPEL_SYSCALL_H__

unsigned long sys_mmap(void *addr, unsigned long len, unsigned long prot, unsigned long flags, unsigned long fd,
		       unsigned long offset);

#endif
