/*
 * Please add here type definitions if
 * syscall prototypes need them.
 *
 * Anything else should go to plain type.h
 */

#ifndef SYSCALL_TYPES_H__
#define SYSCALL_TYPES_H__

#include <sys/time.h>
#include <arpa/inet.h>

#include "types.h"

#ifndef CONFIG_X86_64
# error x86-32 bit mode not yet implemented
#endif

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

#define setns	sys_setns

#endif /* SYSCALL_TYPES_H__ */
