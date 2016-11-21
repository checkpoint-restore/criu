/*
 * Please add here type definitions if
 * syscall prototypes need them.
 *
 * Anything else should go to plain type.h
 */

#ifndef __CR_SYSCALL_TYPES_H__
#define __CR_SYSCALL_TYPES_H__

#include <sys/time.h>
#include <arpa/inet.h>
#include <sched.h>
#include <time.h>
#include <fcntl.h>
#include "int.h"

struct cap_header {
	u32 version;
	int pid;
};

struct cap_data {
	u32 eff;
	u32 prm;
	u32 inh;
};

struct sockaddr;
struct msghdr;
struct rusage;
struct file_handle;
struct robust_list_head;
struct io_event;
struct iocb;
struct timespec;

typedef unsigned long aio_context_t;

struct itimerspec;

#ifndef F_GETFD
#define F_GETFD 1
#endif

struct krlimit {
	unsigned long rlim_cur;
	unsigned long rlim_max;
};

struct siginfo;

/* Type of timers in the kernel.  */
typedef int kernel_timer_t;

#endif /* __CR_SYSCALL_TYPES_H__ */
