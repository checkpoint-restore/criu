#ifndef __ZDTM_PIDFD_H__
#define __ZDTM_PIDFD_H__

#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>

#include "zdtmtst.h"

/*
 * What several pidfd tests need from the kernel and from each other. The
 * helpers are inline so that a test including this header pays for nothing
 * it does not call.
 */

#ifndef SO_PASSPIDFD
#define SO_PASSPIDFD 76
#endif

#ifndef SCM_PIDFD
#define SCM_PIDFD 0x04
#endif

static inline int zdtm_pidfd_send_signal(int pidfd, int sig, siginfo_t *info, unsigned int flags)
{
	return syscall(__NR_pidfd_send_signal, pidfd, sig, info, flags);
}

/* Returns the fdinfo Pid field (-1 for a dead process), or -2 on error */
static inline pid_t zdtm_pidfd_get_pid(int pidfd)
{
	char path[64];
	char line[256];
	pid_t pid = -2;
	FILE *f;

	snprintf(path, sizeof(path), "/proc/self/fdinfo/%d", pidfd);
	f = fopen(path, "r");
	if (!f) {
		pr_perror("fopen %s", path);
		return -2;
	}

	while (fgets(line, sizeof(line), f)) {
		if (sscanf(line, "Pid: %d", &pid) == 1)
			break;
	}

	fclose(f);
	return pid;
}
#endif /* __ZDTM_PIDFD_H__ */
