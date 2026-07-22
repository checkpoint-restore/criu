#ifndef __CR_PIDFD_H__
#define __CR_PIDFD_H__

#include <stdint.h>
#include <sys/ioctl.h>

#include "files.h"
#include "pidfd.pb-c.h"

/*
 * PIDFD_GET_INFO (pidfs ioctl, Linux 6.13) lets us read the exit status of
 * the process a pidfd refers to, though only from Linux 6.15, where pidfs
 * started keeping that status and reporting it as PIDFD_INFO_EXIT. On 6.13
 * and 6.14 the ioctl answers but never has an exit status to give, which is
 * why kerndat probes a reaped child rather than the ioctl's mere presence.
 *
 * The struct layout is versioned by size and baked into the ioctl number, and
 * the kernel serves any request at least as large as the first published
 * version. So we deliberately pin our own copy to that version
 * (PIDFD_INFO_SIZE_VER0 == 64 bytes) rather than track the ones added since:
 * @exit_code, all we need, is its last field. This needs no <linux/pidfd.h>
 * and works unchanged on every kernel that has the ioctl.
 */
struct criu_pidfd_info {
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

/*
 * Only returned by PIDFD_GET_INFO if requested and the task has exited, and
 * only by Linux 6.15 and later (see above).
 */
#define CRIU_PIDFD_INFO_EXIT (1UL << 3)
#define CRIU_PIDFD_GET_INFO  _IOWR(0xFF, 11, struct criu_pidfd_info)

extern const struct fdtype_ops pidfd_dump_ops;
extern struct collect_image_info pidfd_cinfo;
extern int is_pidfd_link(char *link);
extern void init_dead_pidfd_hash(void);
extern int pidfd_query_exit(int pidfd, int *exit_code);
struct pidfd_dump_info {
	PidfdEntry pidfe;
	pid_t pid;
};

#endif /* __CR_PIDFD_H__ */
