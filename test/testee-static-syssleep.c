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

static always_inline long sys_nanosleep(struct timespec *req, struct timespec *rem)
{
	return syscall2(__NR_nanosleep, (unsigned long)req, (unsigned long)rem);
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
	for (;;)
		local_sleep(5);

	return 0;
}
