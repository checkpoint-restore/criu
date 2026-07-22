#ifndef __CR_PIDFD_H__
#define __CR_PIDFD_H__

#include <stdint.h>
#include <sys/ioctl.h>

#include "files.h"
#include "pidfd.pb-c.h"
#include "pidfs.pb-c.h"

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

/*
 * A process that has been reaped stays observable through its struct pid: a
 * pidfd of it can still be held, the kernel can still hand one out for an skb
 * it sent, and pidfs keeps its exit status readable via PIDFD_GET_INFO.
 *
 * To reproduce that, restore forks a stand-in process for each such dead pid,
 * lets everything that needs to reference it do so -- open a pidfd of it, pass
 * its pid to sendmsg() as spoofed SCM_CREDENTIALS -- and only then makes the
 * stand-in die exactly the way the original did. The references then go stale
 * with the right exit status, just as they were before the dump.
 *
 * Stand-ins are shared within a pool by exit status. Through the pidfd itself
 * that makes two dead pids that died the same way indistinguishable, which is
 * what they already were. What does tell them apart is the pid number, still
 * visible as ucred.pid on a socket that also has SO_PASSCRED -- but that is a
 * dump host pid with no meaning after restore, and it is not preserved either
 * way, so sharing costs nothing that was not already lost.
 */
struct dead_pid;

struct dead_pid_pool {
	struct dead_pid *list;
};

extern pid_t dead_pid_get(struct dead_pid_pool *pool, PidfsAttrEntry *attr);
extern int dead_pid_put_all(struct dead_pid_pool *pool);

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
