#ifndef CR_SYSCALL_H_
#define CR_SYSCALL_H_

#include <sys/types.h>

#include "compiler.h"
#include "syscall-codes.h"

#ifdef CONFIG_X86_64

static always_inline long syscall0(int nr)
{
	long ret;
	asm volatile("syscall"
		     : "=a" (ret)
		     : "a" (nr)
		     : "memory");
	return ret;
}

static always_inline long syscall1(int nr, unsigned long arg0)
{
	long ret;
	asm volatile("syscall"
		     : "=a" (ret)
		     : "a" (nr), "D" (arg0)
		     : "memory");
	return ret;
}

static always_inline long syscall2(int nr, unsigned long arg0, unsigned long arg1)
{
	long ret;
	asm volatile("syscall"
		     : "=a" (ret)
		     : "a" (nr), "D" (arg0), "S" (arg1)
		     : "memory");
	return ret;
}

static always_inline long syscall3(int nr, unsigned long arg0, unsigned long arg1,
				     unsigned long arg2)
{
	long ret;
	asm volatile("syscall"
		     : "=a" (ret)
		     : "a" (nr), "D" (arg0), "S" (arg1), "d" (arg2)
		     : "memory");
	return ret;
}

static always_inline long syscall4(int nr, unsigned long arg0, unsigned long arg1,
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

static long always_inline syscall5(int nr, unsigned long arg0, unsigned long arg1,
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

static long always_inline syscall6(int nr, unsigned long arg0, unsigned long arg1,
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

static always_inline unsigned long sys_pause(void)
{
	return syscall0(__NR_pause);
}

static always_inline unsigned long sys_mmap(void *addr, unsigned long len, unsigned long prot,
					      unsigned long flags, unsigned long fd, unsigned long offset)
{
	return syscall6(__NR_mmap, (unsigned long)addr,
			len, prot, flags, fd, offset);
}

static always_inline unsigned long sys_munmap(void *addr,unsigned long len)
{
	return syscall2(__NR_munmap, (unsigned long)addr, len);
}

static always_inline long sys_open(const char *filename, unsigned long flags, unsigned long mode)
{
	return syscall3(__NR_open, (unsigned long)filename, flags, mode);
}

static always_inline long sys_close(int fd)
{
	return syscall1(__NR_close, fd);
}

static always_inline long sys_write(unsigned long fd, const void *buf, unsigned long count)
{
	return syscall3(__NR_write, fd, (unsigned long)buf, count);
}

static always_inline long sys_mincore(unsigned long addr, unsigned long size, void *vec)
{
	return syscall3(__NR_mincore, addr, size, (unsigned long)vec);
}

static always_inline long sys_lseek(unsigned long fd, unsigned long offset, unsigned long origin)
{
	return syscall3(__NR_lseek, fd, offset, origin);
}

static always_inline long sys_mprotect(unsigned long start, unsigned long len, unsigned long prot)
{
	return syscall3(__NR_mprotect, start, len, prot);
}

static always_inline long sys_nanosleep(struct timespec *req, struct timespec *rem)
{
	return syscall2(__NR_nanosleep, (unsigned long)req, (unsigned long)rem);
}

static always_inline long sys_read(unsigned long fd, void *buf, unsigned long count)
{
	return syscall3(__NR_read, fd, (unsigned long)buf, count);
}

/*
 * Note this call expects a signal frame on stack
 * (regs->sp) so be very carefull here!
 */
static always_inline long sys_rt_sigreturn(void)
{
	return syscall0(__NR_rt_sigreturn);
}

#else /* CONFIG_X86_64 */
# error x86-32 bit mode not yet implemented
#endif /* CONFIG_X86_64 */

#endif /* CR_SYSCALL_H_ */
