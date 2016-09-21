/*
 * Please add here type definitions if
 * syscall prototypes need them.
 */

#ifndef COMPEL_SYSCALL_TYPES_H__
#define COMPEL_SYSCALL_TYPES_H__

#include <arpa/inet.h>
#include <sys/time.h>
#include <stdbool.h>
#include <signal.h>
#include <sched.h>
#include <fcntl.h>
#include <time.h>

struct cap_header {
	u32 version;
	int pid;
};

struct cap_data {
	u32 eff;
	u32 prm;
	u32 inh;
};

struct robust_list_head;
struct file_handle;
struct itimerspec;
struct io_event;
struct sockaddr;
struct timespec;
struct siginfo;
struct msghdr;
struct rusage;
struct iocb;

typedef unsigned long aio_context_t;

#ifndef F_GETFD
# define F_GETFD 1
#endif

struct krlimit {
	unsigned long rlim_cur;
	unsigned long rlim_max;
};

/* Type of timers in the kernel.  */
typedef int kernel_timer_t;

#include "asm/std/syscall-types.h"

#endif /* COMPEL_SYSCALL_TYPES_H__ */
