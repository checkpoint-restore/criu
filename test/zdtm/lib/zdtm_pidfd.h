#ifndef __ZDTM_PIDFD_H__
#define __ZDTM_PIDFD_H__

#include <stdio.h>
#include <stdint.h>
#include <signal.h>
#include <unistd.h>
#include <sys/ioctl.h>
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

/* Keep this layout independent of the build host's linux/pidfd.h version. */
struct zdtm_pidfd_info {
	uint64_t mask;
	uint64_t cgroupid;
	uint32_t pid;
	uint32_t tgid;
	uint32_t ppid;
	uint32_t ruid;
	uint32_t rgid;
	uint32_t euid;
	uint32_t egid;
	uint32_t suid;
	uint32_t sgid;
	uint32_t fsuid;
	uint32_t fsgid;
	int32_t exit_code;
};

#define ZDTM_PIDFD_INFO_EXIT (1UL << 3)
#define ZDTM_PIDFD_GET_INFO  _IOWR(0xFF, 11, struct zdtm_pidfd_info)

/*
 * Read the exit status of the process a pidfd refers to. Returns 1 and fills
 * *exit_code (a wait(2)-style status word) if the task exited, 0 if it is
 * alive, and -1 if PIDFD_GET_INFO / PIDFD_INFO_EXIT is unavailable.
 */
static inline int zdtm_pidfd_query_exit(int pidfd, int *exit_code)
{
	struct zdtm_pidfd_info info = { .mask = ZDTM_PIDFD_INFO_EXIT };

	if (ioctl(pidfd, ZDTM_PIDFD_GET_INFO, &info) < 0)
		return -1;
	if (!(info.mask & ZDTM_PIDFD_INFO_EXIT))
		return 0;
	*exit_code = info.exit_code;
	return 1;
}

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
