#ifndef CR_SYSCALL_H_
#define CR_SYSCALL_H_

#include <sys/types.h>

#include "compiler.h"

#ifdef CONFIG_X86_64

static long syscall0(int nr)
{
	long ret;
	asm volatile("syscall"
		     : "=a" (ret)
		     : "a" (nr)
		     : "memory");
	return ret;
}

static long syscall1(int nr, unsigned long arg0)
{
	long ret;
	asm volatile("syscall"
		     : "=a" (ret)
		     : "a" (nr), "D" (arg0)
		     : "memory");
	return ret;
}

static long syscall2(int nr, unsigned long arg0, unsigned long arg1)
{
	long ret;
	asm volatile("syscall"
		     : "=a" (ret)
		     : "a" (nr), "D" (arg0), "S" (arg1)
		     : "memory");
	return ret;
}

static long syscall3(int nr, unsigned long arg0, unsigned long arg1,
		     unsigned long arg2)
{
	long ret;
	asm volatile("syscall"
		     : "=a" (ret)
		     : "a" (nr), "D" (arg0), "S" (arg1), "d" (arg2)
		     : "memory");
	return ret;
}

static long syscall4(int nr, unsigned long arg0, unsigned long arg1,
		     unsigned long arg2, unsigned long arg3)
{
	register unsigned long r10 asm("r10") = r10;
	long ret;

	r10 = arg3;
	asm volatile("syscall"
		     : "=a" (ret)
		     : "a" (nr), "D" (arg0), "S" (arg1), "d" (arg2)
		     : "memory");
	return ret;
}

static long syscall5(int nr, unsigned long arg0, unsigned long arg1,
		     unsigned long arg2, unsigned long arg3,
		     unsigned long arg4)
{
	register unsigned long r10 asm("r10") = r10;
	register unsigned long r8 asm("r8") = r8;
	long ret;

	r10 = arg3;
	r8 = arg4;
	asm volatile("syscall"
		     : "=a" (ret)
		     : "a" (nr), "D" (arg0), "S" (arg1), "d" (arg2)
		     : "memory");
	return ret;
}

static long syscall6(int nr, unsigned long arg0, unsigned long arg1,
		     unsigned long arg2, unsigned long arg3,
		     unsigned long arg4, unsigned long arg5)
{
	register unsigned long r10 asm("r10") = r10;
	register unsigned long r8 asm("r8") = r8;
	register unsigned long r9 asm("r9") = r9;
	long ret;

	r10 = arg3;
	r8 = arg4;
	r9 = arg5;
	asm volatile("syscall"
		     : "=a" (ret)
		     : "a" (nr), "D" (arg0), "S" (arg1), "d" (arg2)
		     : "memory");
	return ret;
}

/*
 * syscall codes
 */
#define __NR_read		0
#define __NR_write		1
#define __NR_open		2
#define __NR_close		3
#define __NR_lseek		8
#define __NR_mmap		9
#define __NR_mprotect		10
#define __NR_munmap		11
#define __NR_brk		12
#define __NR_mincore		27
#define __NR_dup		32
#define __NR_dup2		33
#define __NR_pause		34
#define __NR_nanosleep		35
#define __NR_getpid		39
#define __NR_exit		60

static unsigned long sys_pause(void)
{
	return syscall0(__NR_pause);
}

static unsigned long sys_mmap(void *addr, unsigned long len, unsigned long prot,
			      unsigned long flags, unsigned long fd, unsigned long offset)
{
	return syscall6(__NR_mmap, (unsigned long)addr,
			len, prot, flags, fd, offset);
}

static unsigned long sys_munmap(void *addr,unsigned long len)
{
	return syscall2(__NR_munmap, (unsigned long)addr, len);
}

static long sys_open(const char *filename, unsigned long flags, unsigned long mode)
{
	return syscall3(__NR_open, (unsigned long)filename, flags, mode);
}

static long sys_close(int fd)
{
	return syscall1(__NR_close, fd);
}

static long sys_write(unsigned long fd, const void *buf, unsigned long count)
{
	return syscall3(__NR_write, fd, (unsigned long)buf, count);
}

static long sys_mincore(unsigned long addr, unsigned long size, void *vec)
{
	return syscall3(__NR_mincore, addr, size, (unsigned long)vec);
}

static long sys_lseek(unsigned long fd, unsigned long offset, unsigned long origin)
{
	return syscall3(__NR_lseek, fd, offset, origin);
}

static long sys_mprotect(unsigned long start, unsigned long len, unsigned long prot)
{
	return syscall3(__NR_mprotect, start, len, prot);
}

static long sys_nanosleep(struct timespec *req, struct timespec *rem)
{
	return syscall2(__NR_nanosleep, (unsigned long)req, (unsigned long)rem);
}

static long sys_read(unsigned long fd, void *buf, unsigned long count)
{
	return syscall3(__NR_read, fd, (unsigned long)buf, count);
}

#else /* CONFIG_X86_64 */
# error x86-32 bit mode not yet implemented
#endif /* CONFIG_X86_64 */

#endif /* CR_SYSCALL_H_ */
