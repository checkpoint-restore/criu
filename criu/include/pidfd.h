#ifndef __CR_PIDFD_H__
#define __CR_PIDFD_H__

#include <stdint.h>
#include <sys/ioctl.h>

#include "files.h"
#include "pidfd.pb-c.h"
#include "pidfs.pb-c.h"

/*
 * PIDFD_GET_INFO (pidfs ioctl, Linux 6.13) lets us read the exit status of
 * the process a pidfd refers to. The struct layout is versioned by size and
 * baked into the ioctl number, and the kernel serves any request at least as
 * large as the first published version. So we deliberately pin our own copy
 * to that version (PIDFD_INFO_SIZE_VER0 == 64 bytes) rather than track the
 * ones added since: @exit_code, all we need, is its last field. This needs no
 * <linux/pidfd.h> and works unchanged on every kernel that has the ioctl.
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

/* Only returned by PIDFD_GET_INFO if requested and the task has exited. */
#define CRIU_PIDFD_INFO_EXIT (1UL << 3)
#define CRIU_PIDFD_GET_INFO  _IOWR(0xFF, 11, struct criu_pidfd_info)

/*
 * pidfs serves i_generation through the generic FS_IOC_GETVERSION, which is
 * where the high half of the pidfs cookie lives on a 32-bit kernel. Defined
 * here so we need no <linux/fs.h>, which clashes with <sys/mount.h>.
 */
#ifndef FS_IOC_GETVERSION
#define FS_IOC_GETVERSION _IOR('v', 1, long)
#endif

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
 * Stand-ins are keyed on the pidfs ino of the struct pid they stand in for,
 * in one hashtable shared by everything that restores a reference to a dead
 * pid -- pidfd files and the queued packets of dead senders alike. That is
 * what makes the identities come out right: two references to one dead
 * process get one stand-in, and two dead processes get two, however alike
 * they happen to look. Nothing else about a reaped process is distinctive
 * enough to key on; two of them can share an exit code, a name, everything.
 *
 * An entry with no ino recorded (see pidfs_attr_entry) gets a stand-in of its
 * own, shared with nothing, since there is no way to tell what it is.
 *
 * The table is shared by the whole restore, not private to a task, because a
 * dead sender can be referred to from several tasks at once: two sockets in
 * two tasks can each hold a packet it sent, and a third task can hold a pidfd
 * of it. So it is built while the images are collected, with dead_pid_add()
 * handing out an index per distinct struct pid, and moved into shared memory
 * by dead_pid_prepare() before the task tree is forked.
 *
 * The root task then forks one stand-in per entry from dead_pid_fork_all(),
 * after the whole tree exists -- forking earlier would take pid numbers the
 * restored tasks need -- and before any task starts restoring its files. Every
 * task reads the pids out of the table with dead_pid_get(), so one dead
 * process comes back as one struct pid however many references there are.
 *
 * dead_pid_put_all() makes every stand-in die and reaps it. It runs in the
 * root task once all the tasks have restored all of their files, which is
 * where the last of the references has been taken.
 *
 * A task restoring outside the root task's pid namespace is the exception: a
 * pid number of that namespace means nothing to it, so it forks private
 * stand-ins and disposes of them with dead_pid_put_private() at the end of its
 * own open_fdinfos(). Those are per task, not per namespace, so any two such
 * tasks referring to one dead process get a stand-in each and their receivers
 * see two inos, which is what every task did before this table existed.
 */
extern int dead_pid_add(uint64_t ino, bool has_ino, PidfsAttrEntry *attr);
extern int dead_pid_prepare(void);
extern int dead_pid_fork_all(void);
extern int dead_pid_put_all(void);
extern int dead_pid_put_private(void);
extern pid_t dead_pid_get(int idx);

extern const struct fdtype_ops pidfd_dump_ops;
extern struct collect_image_info pidfd_cinfo;
extern int is_pidfd_link(char *link);
extern void init_dead_pidfd_hash(void);
extern int pidfd_query_exit(int pidfd, int *exit_code);
extern int pidfd_query_ino(int pidfd, uint64_t *ino);
struct pidfd_dump_info {
	PidfdEntry pidfe;
	pid_t pid;
};

#endif /* __CR_PIDFD_H__ */
