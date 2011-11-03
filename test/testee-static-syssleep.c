#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>

#include <sys/wait.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>

#include <sched.h>

#ifndef always_inline
# define always_inline		__always_inline
#endif

#define __NR_write	1
#define __NR_nanosleep 35

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

static always_inline long sys_nanosleep(struct timespec *req, struct timespec *rem)
{
	return syscall2(__NR_nanosleep, (unsigned long)req, (unsigned long)rem);
}

static always_inline long sys_write(unsigned long fd, const void *buf, unsigned long count)
{
	return syscall3(__NR_write, fd, (unsigned long)buf, count);
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

int main(int argc, char *argv[])
{
	const char msg[] = "I'm alive\n";
	for (;;) {
		sys_write(1, msg, sizeof(msg));
		local_sleep(5);
	}

	return 0;
}
