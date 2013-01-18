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

#include "asm/types.h"

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

#ifndef F_GETFD
#define F_GETFD 1
#endif

#ifndef CLONE_NEWNS
#define CLONE_NEWNS	0x00020000
#endif

#ifndef CLONE_NEWPID
#define CLONE_NEWPID	0x20000000
#endif

#ifndef CLONE_NEWUTS
#define CLONE_NEWUTS	0x04000000
#endif

#ifndef CLONE_NEWIPC
#define CLONE_NEWIPC	0x08000000
#endif

#ifndef CLONE_NEWNET
#define CLONE_NEWNET	0x40000000
#endif

#define CLONE_ALLNS	(CLONE_NEWPID | CLONE_NEWNET | CLONE_NEWIPC | CLONE_NEWUTS | CLONE_NEWNS)

#define setns	sys_setns

struct rlimit;

struct krlimit {
	unsigned long rlim_cur;
	unsigned long rlim_max;
};

#endif /* __CR_SYSCALL_TYPES_H__ */
