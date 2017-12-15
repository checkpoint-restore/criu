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
#include <stdint.h>
#include <sched.h>
#include <fcntl.h>
#include <time.h>

#include "common/bitsperlong.h"

struct cap_header {
	uint32_t version;
	int pid;
};

struct cap_data {
	uint32_t eff;
	uint32_t prm;
	uint32_t inh;
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

#include <compel/plugins/std/asm/syscall-types.h>


extern long sys_preadv_raw(int fd, struct iovec *iov, unsigned long nr, unsigned long pos_l, unsigned long pos_h);

static inline long sys_preadv(int fd, struct iovec *iov, unsigned long nr, off_t off)
{
#if BITS_PER_LONG == 64
	return sys_preadv_raw(fd, iov, nr, off, 0);
#elif BITS_PER_LONG == 32
	return sys_preadv_raw(fd, iov, nr, off, ((uint64_t)off) >> 32);
#else
#	error "BITS_PER_LONG isn't defined"
#endif
}

#endif /* COMPEL_SYSCALL_TYPES_H__ */
