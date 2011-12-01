#ifndef CR_SYSCALL_H_
#define CR_SYSCALL_H_

#include <sys/types.h>

#include "types.h"
#include "compiler.h"
#include "syscall-codes.h"

#ifdef CONFIG_X86_64

typedef struct {
	unsigned long sig[1];
} rt_sigset_t;

static always_inline long syscall0(int nr)
{
	long ret;
	asm volatile(
		"movl %1, %%eax		\t\n"
		"syscall		\t\n"
		"movq %%rax, %0		\t\n"
		: "=r"(ret)
		: "g" ((int)nr)
		: "rax", "memory");
	return ret;
}

static always_inline long syscall1(int nr, unsigned long arg0)
{
	long ret;
	asm volatile(
		"movl %1, %%eax		\t\n"
		"movq %2, %%rdi		\t\n"
		"syscall		\t\n"
		"movq %%rax, %0		\t\n"
		: "=r"(ret)
		: "g" ((int)nr), "g" (arg0)
		: "rax", "rdi", "memory");
	return ret;
}

static always_inline long syscall2(int nr, unsigned long arg0, unsigned long arg1)
{
	long ret;
	asm volatile(
		"movl %1, %%eax		\t\n"
		"movq %2, %%rdi		\t\n"
		"movq %3, %%rsi		\t\n"
		"syscall		\t\n"
		"movq %%rax, %0		\t\n"
		: "=r"(ret)
		: "g" ((int)nr), "g" (arg0), "g" (arg1)
		: "rax", "rdi", "rsi", "memory");
	return ret;
}

static always_inline long syscall3(int nr, unsigned long arg0, unsigned long arg1,
				   unsigned long arg2)
{
	long ret;
	asm volatile(
		"movl %1, %%eax		\t\n"
		"movq %2, %%rdi		\t\n"
		"movq %3, %%rsi		\t\n"
		"movq %4, %%rdx		\t\n"
		"syscall		\t\n"
		"movq %%rax, %0		\t\n"
		: "=r"(ret)
		: "g" ((int)nr), "g" (arg0), "g" (arg1), "g" (arg2)
		: "rax", "rdi", "rsi", "rdx", "memory");
	return ret;
}

static always_inline long syscall4(int nr, unsigned long arg0, unsigned long arg1,
				   unsigned long arg2, unsigned long arg3)
{
	long ret;
	asm volatile(
		"movl %1, %%eax		\t\n"
		"movq %2, %%rdi		\t\n"
		"movq %3, %%rsi		\t\n"
		"movq %4, %%rdx		\t\n"
		"movq %5, %%r10		\t\n"
		"syscall		\t\n"
		"movq %%rax, %0		\t\n"
		: "=r"(ret)
		: "g" ((int)nr), "g" (arg0), "g" (arg1), "g" (arg2),
			"g" (arg3)
		: "rax", "rdi", "rsi", "rdx", "r10", "memory");
	return ret;
}

static long always_inline syscall5(int nr, unsigned long arg0, unsigned long arg1,
				   unsigned long arg2, unsigned long arg3,
				   unsigned long arg4)
{
	long ret;
	asm volatile(
		"movl %1, %%eax		\t\n"
		"movq %2, %%rdi		\t\n"
		"movq %3, %%rsi		\t\n"
		"movq %4, %%rdx		\t\n"
		"movq %5, %%r10		\t\n"
		"movq %6, %%r8		\t\n"
		"syscall		\t\n"
		"movq %%rax, %0		\t\n"
		: "=r"(ret)
		: "g" ((int)nr), "g" (arg0), "g" (arg1), "g" (arg2),
			"g" (arg3), "g" (arg4)
		: "rax", "rdi", "rsi", "rdx", "r10", "r8", "memory");
	return ret;
}

static long always_inline syscall6(int nr, unsigned long arg0, unsigned long arg1,
				   unsigned long arg2, unsigned long arg3,
				   unsigned long arg4, unsigned long arg5)
{
	long ret;
	asm volatile(
		"movl %1, %%eax		\t\n"
		"movq %2, %%rdi		\t\n"
		"movq %3, %%rsi		\t\n"
		"movq %4, %%rdx		\t\n"
		"movq %5, %%r10		\t\n"
		"movq %6, %%r8		\t\n"
		"movq %7, %%r9		\t\n"
		"syscall		\t\n"
		"movq %%rax, %0		\t\n"
		: "=r"(ret)
		: "g" ((int)nr), "g" (arg0), "g" (arg1), "g" (arg2),
			"g" (arg3), "g" (arg4), "g" (arg5)
		: "rax", "rdi", "rsi", "rdx", "r10", "r8", "r9", "memory");
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

struct sigaction;

static always_inline long sys_sigaction(int signum, const struct sigaction *act, struct sigaction *oldact)
{
	return syscall4(__NR_rt_sigaction, signum, (unsigned long) act, (unsigned long) oldact, sizeof(rt_sigset_t));
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

static always_inline long sys_exit(unsigned long error_code)
{
	return syscall1(__NR_exit, error_code);
}

static always_inline unsigned long sys_getpid(void)
{
	return syscall0(__NR_getpid);
}

static always_inline unsigned long sys_gettid(void)
{
	return syscall0(__NR_gettid);
}

static always_inline long sys_unlink(char *pathname)
{
	return syscall1(__NR_unlink, (unsigned long)pathname);
}

/*
 * Note this call expects a signal frame on stack
 * (regs->sp) so be very carefull here!
 */
static always_inline long sys_rt_sigreturn(void)
{
	return syscall0(__NR_rt_sigreturn);
}

static always_inline long sys_set_thread_area(user_desc_t *info)
{
	return syscall1(__NR_set_thread_area, (long)info);
}

static always_inline long sys_get_thread_area(user_desc_t *info)
{
	return syscall1(__NR_get_thread_area, (long)info);
}

static always_inline long sys_arch_prctl(int code, void *addr)
{
	return syscall2(__NR_arch_prctl, code, (unsigned long)addr);
}

static always_inline long sys_prctl(int code, unsigned long arg2, unsigned long arg3,
				    unsigned long arg4, unsigned long arg5)
{
	return syscall5(__NR_prctl, code, arg2, arg3, arg4, arg5);
}

static always_inline long sys_clone(unsigned long flags, void *child_stack,
				    void *parent_tid, void *child_tid)
{
	return syscall4(__NR_clone, flags, (unsigned long)child_stack,
			(unsigned long)parent_tid, (unsigned long)child_tid);
}

static always_inline long sys_futex(u32 *uaddr, int op, u32 val,
				    struct timespec *utime,
				    u32 *uaddr2, u32 val3)
{
	return syscall6(__NR_futex, (unsigned long)uaddr,
			(unsigned long)op, (unsigned long)val,
			(unsigned long)utime,
			(unsigned long)uaddr2,
			(unsigned long)val3);
}

static always_inline long sys_flock(unsigned long fd, unsigned long cmd)
{
	return syscall2(__NR_flock, fd, cmd);
}

static void always_inline local_sleep(long seconds)
{
	struct timespec req, rem;

	req = (struct timespec){
		.tv_sec		= seconds,
		.tv_nsec	= 0,
	};

	sys_nanosleep(&req, &rem);
}

#else /* CONFIG_X86_64 */
# error x86-32 bit mode not yet implemented
#endif /* CONFIG_X86_64 */

#endif /* CR_SYSCALL_H_ */
