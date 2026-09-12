#include "common/lock.h"
#include "imgset.h"
#include "kerndat.h"
#include "pidfd.h"
#include "fdinfo.h"
#include "pidfd.pb-c.h"
#include "protobuf.h"
#include "pstree.h"
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <signal.h>
#include "common/bug.h"
#include "common/compiler.h"
#include "rst-malloc.h"
#include "util.h"

#include "compel/plugins/std/syscall-codes.h"

#undef LOG_PREFIX
#define LOG_PREFIX "pidfd: "

#ifndef PIDFD_THREAD
#define PIDFD_THREAD O_EXCL
#endif

struct pidfd_info {
	PidfdEntry *pidfe;
	struct file_desc d;

	struct dead_pidfd *dead;
	struct pidfd_info *next;
};

struct dead_pidfd {
	uint64_t ino;
	int creator_id;
	int dead_pid_idx;

	struct hlist_node hash;
	struct pidfd_info *list;
};

#define DEAD_PIDFD_HASH_SIZE 32
static struct hlist_head dead_pidfd_hash[DEAD_PIDFD_HASH_SIZE];

void init_dead_pidfd_hash(void)
{
	for (int i = 0; i < DEAD_PIDFD_HASH_SIZE; i++)
		INIT_HLIST_HEAD(&dead_pidfd_hash[i]);
}

static struct dead_pidfd *lookup_dead_pidfd(uint64_t ino)
{
	struct dead_pidfd *dead;
	struct hlist_head *chain;

	chain = &dead_pidfd_hash[ino % DEAD_PIDFD_HASH_SIZE];
	hlist_for_each_entry(dead, chain, hash) {
		if (dead->ino == ino) {
			return dead;
		}
	}

	return NULL;
}

/*
 * Query the exit status of the process a pidfd refers to via PIDFD_GET_INFO.
 * Returns 1 and fills *exit_code (a wait(2)-style status word) if the task has
 * exited, 0 if it is still alive, and -1 if the ioctl is unavailable or failed
 * (the caller should fall back to a coarser method).
 */
int pidfd_query_exit(int pidfd, int *exit_code)
{
	struct criu_pidfd_info info = { .mask = CRIU_PIDFD_INFO_EXIT };

	BUILD_BUG_ON(sizeof(struct criu_pidfd_info) != 64);

	if (ioctl(pidfd, CRIU_PIDFD_GET_INFO, &info) < 0) {
		pr_debug("PIDFD_GET_INFO failed: %s\n", strerror(errno));
		return -1;
	}

	if (!(info.mask & CRIU_PIDFD_INFO_EXIT))
		return 0;

	*exit_code = info.exit_code;
	return 1;
}

/*
 * Read the pidfs inode number of the struct pid @pidfd refers to. This is the
 * identity of the process: pidfs hands every struct pid a unique inode (Linux
 * 6.9), and comparing inode numbers is how the kernel itself tells two pidfds
 * apart.
 *
 * Returns 0 and fills *ino on success, -1 on failure. Note that this is not
 * the convention pidfd_query_exit() above uses -- that one has a third answer
 * to give ("the task is still alive"), this one does not.
 */
int pidfd_query_ino(int pidfd, uint64_t *ino)
{
	unsigned int gen = 0;
	struct stat st;

	if (fstat(pidfd, &st) < 0) {
		pr_debug("fstat on pidfd %d failed: %s\n", pidfd, strerror(errno));
		return -1;
	}

	*ino = st.st_ino;

	/*
	 * The cookie pidfs hands a struct pid is 64 bits wide, but an inode
	 * number is a long: on a 32-bit kernel pidfs_init_inode() keeps only
	 * the low half in i_ino and puts the high half in i_generation, which
	 * FS_IOC_GETVERSION reads back. Fold it in, or two struct pids 2^32
	 * apart would look like one. On a 64-bit kernel the generation is
	 * always 0, so this is a no-op there, and a kernel too old to serve
	 * the ioctl leaves us the ino we already have.
	 */
	if (ioctl(pidfd, FS_IOC_GETVERSION, &gen) == 0)
		*ino |= (uint64_t)gen << 32;

	return 0;
}

int is_pidfd_link(char *link)
{
	/*
	* pidfs was introduced in Linux 6.9
	* before which anonymous-inodes were used
	*/
	return is_anon_link_type(link, "[pidfd]");
}

static void pr_info_pidfd(char *action, PidfdEntry *pidfe)
{
	pr_info("%s: id %#08x flags %u NSpid %d ino %" PRIu64 "\n",
		action, pidfe->id, pidfe->flags, pidfe->nspid, pidfe->ino
	);
}

static int dump_one_pidfd(int pidfd, u32 id, const struct fd_parms *p)
{
	struct pidfd_dump_info pidfd_info = {.pidfe = PIDFD_ENTRY__INIT};
	PidfsAttrEntry attr = PIDFS_ATTR_ENTRY__INIT;
	FileEntry fe = FILE_ENTRY__INIT;
	uint64_t ino;
	int exit_code;

	if (parse_fdinfo(pidfd, FD_TYPES__PIDFD, &pidfd_info))
		return -1;

	/*
	 * parse_fdinfo() has read the ino: line of /proc/pid/fdinfo/N, which
	 * is only the inode's i_ino. Prefer what the fd itself tells us: on a
	 * 32-bit kernel i_ino is the low half of the pidfs cookie and
	 * pidfd_query_ino() folds the high half back in, which is also how a
	 * queued packet's sender is identified in sk-queue.c. Reading them the
	 * same way is what lets a pidfd file and a packet of one dead process
	 * land on one stand-in. Fall back on the fdinfo value if the fd can't
	 * be stat()ed.
	 */
	if (pidfd_query_ino(pidfd, &ino) == 0)
		pidfd_info.pidfe.ino = ino;

	if (p->flags & PIDFD_THREAD) {
		pr_err("PIDFD_THREAD flag is currently not supported\n");
		return -1;
	}

	/*
	* Check if the pid pidfd refers to is part of process tree
	* This ensures the process will exist on restore.
	*/
	if (pidfd_info.pid != -1 && !pstree_item_by_real(pidfd_info.pid)) {
		pr_err("pidfd pid %d is not a part of process tree..\n",
			pidfd_info.pid);
		return -1;
	}

	/*
	 * The task has been reaped, so all that is left of it is what pidfs
	 * stashed on its struct pid. Save the exit status, so that the
	 * stand-in process restore forks for this dead pid can die the same
	 * way and PIDFD_GET_INFO keeps reporting it.
	 */
	if (pidfd_info.pid == -1 && kdat.has_pidfd_get_info &&
	    pidfd_query_exit(pidfd, &exit_code) > 0) {
		attr.has_exit_code = true;
		attr.exit_code = exit_code;
		pidfd_info.pidfe.attr = &attr;
	}

	pidfd_info.pidfe.id = id;
	pidfd_info.pidfe.flags = (p->flags & ~O_RDWR);
	pidfd_info.pidfe.fown = (FownEntry *)&p->fown;

	fe.type = FD_TYPES__PIDFD;
	fe.id = pidfd_info.pidfe.id;
	fe.pidfd = &pidfd_info.pidfe;

	pr_info_pidfd("Dumping", &pidfd_info.pidfe);
	return pb_write_one(img_from_set(glob_imgset, CR_FD_FILES), &fe, PB_FILE);
}

const struct fdtype_ops pidfd_dump_ops = {
	.type = FD_TYPES__PIDFD,
	.dump = dump_one_pidfd,
};

static int pidfd_open(pid_t pid, int flags)
{
	return syscall(__NR_pidfd_open, pid, flags);
}

static int create_tmp_process(void)
{
	int tmp_process;
	tmp_process = fork();
	if (tmp_process < 0) {
		pr_perror("Could not fork");
		return -1;
	} else if (tmp_process == 0) {
		/* Nothing would reap us if criu died before kill_helper(). */
		prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0);
		/* We need none of the task's files, see create_status_helper(). */
		close_fds(3);
		while(1)
			sleep(1);
	}
	return tmp_process;
}

/*
 * A restore-time stand-in for a process that was already dead at dump time.
 * Without a recorded status the original exit status is unknown and a plain
 * SIGKILL is the best we can reproduce.
 *
 * These live in shared memory: the table is built while the images are
 * collected, before the task tree is forked, and the pids are filled in by
 * the root task once the whole tree exists. Every restoring task then reads
 * the same pid for the same dead process, which is what makes one dead sender
 * come back as one struct pid no matter how many tasks refer to it.
 */
struct dead_pid {
	uint64_t ino;
	uint32_t dump_pid;
	bool has_ino;
	bool has_dump_pid;
	bool has_status;
	int status;
	pid_t pid;
};

static struct dead_pid *dead_pids;
static unsigned int nr_dead_pids;

/* Collect-time staging area, see dead_pid_add() and dead_pid_prepare(). */
static struct dead_pid *dead_pids_buf;
static unsigned int dead_pids_cap;

/*
 * Does @dp stand in for the struct pid described by the other arguments?
 *
 * The pidfs ino is the real identity and is compared on its own. Only where
 * there is none do we fall back on the pid number the process had on the dump
 * host: that is not an identity, since pid numbers are reused, but two dead
 * senders of one image that share a number are almost always one process, and
 * the alternative is a stand-in per reference. An ino-less entry is never
 * matched against one that has an ino -- there is no way to tell whether they
 * are the same, and merging them would be a guess in the other direction.
 */
static bool dead_pid_matches(struct dead_pid *dp, uint64_t ino, bool has_ino, uint32_t dump_pid,
			     bool has_dump_pid)
{
	if (has_ino)
		return dp->has_ino && dp->ino == ino;
	if (has_dump_pid)
		return !dp->has_ino && dp->has_dump_pid && dp->dump_pid == dump_pid;
	return false;
}

/*
 * Register a reference to a dead struct pid, and return the index of the
 * stand-in that will represent it. @has_ino is false when the dump could not
 * record a pidfs identity, in which case @attr's dump host pid is used
 * instead, and an entry with neither gets a stand-in all of its own rather
 * than one shared by guesswork. @attr may be NULL, or carry no exit code,
 * when the way the process died is not known.
 *
 * Called while collecting images, and never concurrently, so no locking is
 * needed here. Note that the callers are not all in one process: pidfd files
 * are collected from the files image in crtools_prepare_shared(), which runs
 * in criu itself, while queued packets are collected in root_prepare_shared(),
 * which runs in the root task criu has forked by then. The staging table below
 * survives that fork like the rest of criu's memory, so the root task goes on
 * adding to what criu started. Anything that moves either collection has to
 * keep them on that one line of descent, and dead_pid_prepare() after both.
 */
int dead_pid_add(uint64_t ino, bool has_ino, PidfsAttrEntry *attr)
{
	bool has_status = attr && attr->has_exit_code;
	int status = has_status ? attr->exit_code : 0;
	bool has_dump_pid = attr && attr->has_dump_pid;
	uint32_t dump_pid = has_dump_pid ? attr->dump_pid : 0;
	struct dead_pid *dp;
	unsigned int i;

	/* The table is closed once dead_pid_prepare() has moved it. */
	BUG_ON(dead_pids != NULL);

	/*
	 * A stand-in can only reproduce a status it can die with. Anything
	 * else would be silently restored as a plain exit(1), so refuse it
	 * here rather than hand out a stand-in that lies about how the
	 * process died.
	 */
	if (has_status && !WIFEXITED(status) && !WIFSIGNALED(status)) {
		pr_err("Dead pid exit status %#x is neither an exit nor a signal\n", status);
		return -1;
	}

	for (i = 0; i < nr_dead_pids; i++) {
		dp = &dead_pids_buf[i];
		if (!dead_pid_matches(dp, ino, has_ino, dump_pid, has_dump_pid))
			continue;
		/*
		 * The same struct pid seen from another reference. It may be
		 * the one that knows how the process died: a queued packet
		 * carries an exit code only where the kernel would hand out a
		 * pidfd for a reaped sender.
		 */
		if (has_status && !dp->has_status) {
			dp->has_status = true;
			dp->status = status;
		} else if (has_status && dp->status != status) {
			/*
			 * Two references disagree about how one process died, so
			 * one of them is wrong. Most likely they are not one
			 * process at all and dead_pid_matches() paired them on
			 * the dump host pid, which it only falls back on because
			 * there is nothing better -- pid numbers are reused.
			 * Keep the status we already have, since the alternative
			 * is no less of a guess, and say so.
			 */
			pr_warn("Dead pid %u is claimed to have died both as %#x and as %#x, keeping the first\n",
				i, dp->status, status);
		}
		return i;
	}

	if (nr_dead_pids == dead_pids_cap) {
		unsigned int cap = dead_pids_cap ? dead_pids_cap * 2 : 8;

		if (xrealloc_safe(&dead_pids_buf, cap * sizeof(*dead_pids_buf)))
			return -1;
		dead_pids_cap = cap;
	}

	dp = &dead_pids_buf[nr_dead_pids];
	dp->ino = ino;
	dp->has_ino = has_ino;
	dp->dump_pid = dump_pid;
	dp->has_dump_pid = has_dump_pid;
	dp->has_status = has_status;
	dp->status = status;
	dp->pid = 0;

	if (has_ino)
		pr_debug("Dead pid %u is the struct pid with ino %" PRIu64 "\n", nr_dead_pids, ino);
	else if (has_dump_pid)
		pr_debug("Dead pid %u has no ino, keyed on dump host pid %u\n", nr_dead_pids, dump_pid);
	else
		pr_debug("Dead pid %u is of unknown identity\n", nr_dead_pids);

	return nr_dead_pids++;
}

/*
 * Move the table into memory shared with everything the restore forks from
 * here on. Call this once all the images that can reference a dead pid are
 * collected and before the task tree is created.
 */
int dead_pid_prepare(void)
{
	size_t size;

	if (!nr_dead_pids)
		return 0;

	size = nr_dead_pids * sizeof(*dead_pids);
	dead_pids = shmalloc(size);
	if (!dead_pids) {
		pr_err("Can't allocate shared memory for %u dead pids\n", nr_dead_pids);
		return -1;
	}

	memcpy(dead_pids, dead_pids_buf, size);
	xfree(dead_pids_buf);
	dead_pids_buf = NULL;
	dead_pids_cap = 0;

	pr_info("%u dead pid stand-in(s) to fork\n", nr_dead_pids);
	return 0;
}

/*
 * The signal a status helper waits for. Any signal would do: it is blocked
 * from the moment the helper is forked (criu restore runs with signals
 * blocked), so it can never be lost or act early, and the helper consumes it
 * with sigwait() rather than letting it have any effect of its own. That also
 * leaves it free to die *by* this signal, if that is how the process it
 * stands in for died.
 */
#define DEAD_PID_GO SIGUSR1

/*
 * Fork a helper that waits until we tell it to die, then reproduces an
 * arbitrary wait(2) status: it exits with a given code or raises a given
 * signal. This is how a stand-in for a dead pid gets the exit status the
 * process it stands in for had. Tell it to die with kill_status_helper().
 *
 * @status is passed by nothing more than the fork: the child gets its own
 * copy along with the rest of our memory. Deliberately so -- a helper must
 * hold no file descriptor of ours, since it outlives the call that forked it
 * and any fd it kept would sit in the way of a file still to be restored.
 */
static int create_status_helper(int status)
{
	pid_t pid;

	pid = fork();
	if (pid < 0) {
		pr_perror("Could not fork status helper");
		return -1;
	}

	if (pid == 0) {
		sigset_t set;
		int sig;

		/*
		 * Nothing would reap us if criu died before it got around to
		 * kill_status_helper().
		 */
		prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0);
		/*
		 * fork() handed us a copy of every file our parent has open,
		 * and we outlive the call that forked us. Drop them, or we
		 * would pin the other end of a pipe or a socket well past the
		 * point it was meant to be closed.
		 */
		close_fds(3);

		sigemptyset(&set);
		sigaddset(&set, DEAD_PID_GO);
		sigprocmask(SIG_BLOCK, &set, NULL);
		if (sigwait(&set, &sig) != 0)
			_exit(1);

		if (WIFEXITED(status)) {
			_exit(WEXITSTATUS(status));
		} else if (WIFSIGNALED(status)) {
			sigset_t unblock;

			sig = WTERMSIG(status);

			/*
			 * We are forked from a criu process that runs with
			 * signals blocked, so unblock the one we are about to
			 * raise -- otherwise it would only become pending and
			 * we would fall through to _exit() below.
			 */
			sigemptyset(&unblock);
			sigaddset(&unblock, sig);
			sigprocmask(SIG_UNBLOCK, &unblock, NULL);

			/*
			 * Don't dump core for a fatal-signal death. A side
			 * effect is that the restored exit status never carries
			 * the WCOREDUMP() bit, even if the process we stand in
			 * for did dump core; reproducing that bit (and the
			 * pidfs coredump attributes along with it) is
			 * deliberately skipped, and kill_status_helper() only
			 * checks the terminating signal.
			 */
			prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
			signal(sig, SIG_DFL);
			raise(sig);
		}
		_exit(1);
	}

	return pid;
}

/*
 * Block SIGCHLD to prevent interfering from sigchld_handler() and to properly
 * handle the tmp process termination without a race condition. A similar
 * approach is used in cr_system().
 */
static int helper_block_sigchld(sigset_t *oldmask)
{
	sigset_t blockmask;

	sigemptyset(oldmask);
	sigemptyset(&blockmask);
	sigaddset(&blockmask, SIGCHLD);
	if (sigprocmask(SIG_BLOCK, &blockmask, oldmask) == -1) {
		pr_perror("Cannot set mask of blocked signals");
		return -1;
	}
	return 0;
}

static int kill_helper(pid_t pid)
{
	sigset_t oldmask;
	int ret = -1;
	int status;

	if (helper_block_sigchld(&oldmask))
		return -1;

	if (kill(pid, SIGKILL) < 0) {
		pr_perror("Could not kill temporary process with pid: %d", pid);
		goto out;
	}

	if (waitpid(pid, &status, 0) != pid) {
		pr_perror("Could not wait on temporary process with pid: %d", pid);
		goto out;
	}

	if (!WIFSIGNALED(status)) {
		pr_err("Expected temporary process to be terminated by a signal\n");
		goto out;
	}

	if (WTERMSIG(status) != SIGKILL) {
		pr_err("Expected temporary process to be terminated by SIGKILL\n");
		goto out;
	}

	ret = 0;
out:
	/*
	 * Unblock on the way out however we got here. Leaving SIGCHLD blocked
	 * would keep sigchld_handler() from ever running again, in a task that
	 * has a whole restore still ahead of it.
	 */
	if (sigprocmask(SIG_SETMASK, &oldmask, NULL) == -1) {
		pr_perror("Cannot clear blocked signals");
		ret = -1;
	}
	return ret;
}

/*
 * Make a create_status_helper() child die with @status (a wait(2)-style
 * status word) and reap it, verifying it died exactly as asked.
 */
static int kill_status_helper(pid_t pid, int status)
{
	sigset_t oldmask;
	int wstatus;
	int ret = -1;
	bool blocked = false, reaped = false;

	if (helper_block_sigchld(&oldmask))
		goto out;
	blocked = true;

	if (kill(pid, DEAD_PID_GO) < 0) {
		pr_perror("Could not signal status helper %d to exit", pid);
		goto out;
	}

	if (waitpid(pid, &wstatus, 0) != pid) {
		pr_perror("Could not wait on status helper with pid: %d", pid);
		goto out;
	}
	reaped = true;

	if (WIFEXITED(status)) {
		if (!WIFEXITED(wstatus) || WEXITSTATUS(wstatus) != WEXITSTATUS(status)) {
			pr_err("Status helper %d did not exit with code %d\n", pid, WEXITSTATUS(status));
			goto out;
		}
	} else if (WIFSIGNALED(status)) {
		if (!WIFSIGNALED(wstatus) || WTERMSIG(wstatus) != WTERMSIG(status)) {
			pr_err("Status helper %d was not killed by signal %d\n", pid, WTERMSIG(status));
			goto out;
		}
	} else {
		/* dead_pid_add() rejects these, so getting here is a bug. */
		pr_err("Can't reproduce status %#x asked of helper %d\n", status, pid);
		goto out;
	}

	ret = 0;
out:
	/*
	 * On the error paths the child may still be running -- never signalled
	 * at all, or signalled but not reaped. Kill and reap it so we neither
	 * leak a zombie nor leave SIGCHLD blocked in the caller.
	 */
	if (!reaped && pid > 0) {
		kill(pid, SIGKILL);
		waitpid(pid, NULL, 0);
	}
	if (blocked && sigprocmask(SIG_SETMASK, &oldmask, NULL) == -1) {
		pr_perror("Cannot clear blocked signals");
		ret = -1;
	}
	return ret;
}

static pid_t dead_pid_fork_one(struct dead_pid *dp)
{
	if (dp->has_status)
		return create_status_helper(dp->status);
	return create_tmp_process();
}

static int dead_pid_kill_one(struct dead_pid *dp, pid_t pid)
{
	if (dp->has_status)
		return kill_status_helper(pid, dp->status);
	return kill_helper(pid);
}

/*
 * Fork a stand-in for every dead pid the images referred to. Called by the
 * root task once the whole task tree exists -- forking earlier would take pid
 * numbers the restored tasks need -- and before any task starts restoring its
 * files, so the pids are there by the time anything looks them up.
 */
int dead_pid_fork_all(void)
{
	unsigned int i;

	for (i = 0; i < nr_dead_pids; i++) {
		pid_t pid;

		pid = dead_pid_fork_one(&dead_pids[i]);
		if (pid < 0) {
			dead_pid_put_all();
			return -1;
		}

		dead_pids[i].pid = pid;
		pr_debug("Forked stand-in %d for dead pid %u\n", pid, i);
	}

	return 0;
}

/*
 * Make every stand-in die the way the process it stands in for did, and reap
 * it. Called by the root task once all the tasks have restored all of their
 * files: each reference taken by then -- an open pidfd, an skb holding the
 * struct pid -- keeps the pid around, so it goes stale exactly as it was
 * before the dump.
 */
int dead_pid_put_all(void)
{
	unsigned int i;
	int ret = 0;

	for (i = 0; i < nr_dead_pids; i++) {
		struct dead_pid *dp = &dead_pids[i];

		if (dp->pid <= 0)
			continue;
		if (dead_pid_kill_one(dp, dp->pid))
			ret = -1;
		dp->pid = 0;
	}

	return ret;
}

/*
 * A task restoring outside the root task's pid namespace can't use the shared
 * stand-ins: they are children of the root task, and the pid number we hand to
 * pidfd_open(), or spoof in an SCM_CREDENTIALS cmsg, is resolved in the pid
 * namespace of the task that uses it. Such a task forks its own stand-ins
 * instead and disposes of them at the end of its own open_fdinfos().
 *
 * These are per task, not per namespace, so any two tasks outside the root pid
 * namespace that refer to one dead process get a stand-in each and their
 * receivers see two inos -- which is what every task did before this table
 * existed. Identities still come out right within one task.
 */
struct dead_pid_private {
	struct dead_pid_private *next;
	unsigned int idx;
	pid_t pid;
};

static struct dead_pid_private *dead_pid_private_list;

static bool dead_pid_shared(void)
{
	if (!current || !current->ids || !root_item->ids)
		return true;
	if (!current->ids->has_pid_ns_id || !root_item->ids->has_pid_ns_id)
		return true;

	return current->ids->pid_ns_id == root_item->ids->pid_ns_id;
}

static pid_t dead_pid_get_private(unsigned int idx)
{
	struct dead_pid_private *p;
	pid_t pid;

	for (p = dead_pid_private_list; p; p = p->next) {
		if (p->idx == idx)
			return p->pid;
	}

	pid = dead_pid_fork_one(&dead_pids[idx]);
	if (pid < 0)
		return -1;

	p = xmalloc(sizeof(*p));
	if (!p) {
		dead_pid_kill_one(&dead_pids[idx], pid);
		return -1;
	}

	p->idx = idx;
	p->pid = pid;
	p->next = dead_pid_private_list;
	dead_pid_private_list = p;

	pr_debug("Forked a private stand-in %d for dead pid %u\n", pid, idx);
	return pid;
}

int dead_pid_put_private(void)
{
	struct dead_pid_private *p, *next;
	int ret = 0;

	for (p = dead_pid_private_list; p; p = next) {
		next = p->next;
		if (dead_pid_kill_one(&dead_pids[p->idx], p->pid))
			ret = -1;
		xfree(p);
	}
	dead_pid_private_list = NULL;

	return ret;
}

/*
 * Return the pid of the stand-in for the dead pid registered under @idx by
 * dead_pid_add().
 */
pid_t dead_pid_get(int idx)
{
	if (idx < 0 || (unsigned int)idx >= nr_dead_pids) {
		pr_err("Bogus dead pid index %d\n", idx);
		return -1;
	}

	if (!dead_pid_shared())
		return dead_pid_get_private(idx);

	if (dead_pids[idx].pid <= 0) {
		pr_err("No stand-in was forked for dead pid %d\n", idx);
		return -1;
	}

	return dead_pids[idx].pid;
}

static int open_one_pidfd(struct file_desc *d, int *new_fd)
{
	struct pidfd_info *info, *child;
	struct dead_pidfd *dead = NULL;
	pid_t pid;
	int pidfd = -1;

	info = container_of(d, struct pidfd_info, d);
	if (info->pidfe->nspid != -1) {
		pidfd = pidfd_open(info->pidfe->nspid, info->pidfe->flags);
		if (pidfd < 0) {
			pr_perror("Could not open pidfd for %d", info->pidfe->nspid);
			goto err_close;
		}
		goto out;
	}

	dead = info->dead;
	BUG_ON(!dead);

	if (dead->creator_id != info->pidfe->id) {
		int ret = recv_desc_from_peer(&info->d, &pidfd);
		if (ret != 0) {
			if (ret != 1)
				pr_err("Can't get fd\n");
			return ret;
		}
		goto out;
	}

	/*
	 * Nothing of the original process is left but its struct pid, so stand
	 * in for it with a process that dies the way the original did. The
	 * stand-in was forked by the root task and is keyed on the pidfs ino,
	 * so everything that refers to the same dead process -- another pidfd,
	 * a queued packet it sent, in this task or in any other -- lands on
	 * this very same one.
	 */
	pid = dead_pid_get(dead->dead_pid_idx);
	if (pid < 0)
		goto err_close;

	for (child = dead->list; child; child = child->next) {
		int cfd;

		if (child == info)
			continue;
		cfd = pidfd_open(pid, child->pidfe->flags);
		if (cfd < 0) {
			pr_perror("Could not open pidfd for %d", child->pidfe->nspid);
			goto err_close;
		}

		if (send_desc_to_peer(cfd, &child->d)) {
			pr_perror("Can't send file descriptor");
			close(cfd);
			goto err_close;
		}
		close(cfd);
	}

	pidfd = pidfd_open(pid, info->pidfe->flags);
	if (pidfd < 0) {
		pr_perror("Could not open pidfd for %d", info->pidfe->nspid);
		goto err_close;
	}
out:
	if (rst_file_params(pidfd, info->pidfe->fown, info->pidfe->flags)) {
		goto err_close;
	}

	*new_fd = pidfd;
	return 0;
err_close:
	if (pidfd >= 0)
		close(pidfd);
	pr_err("Can't create pidfd %#08x NSpid: %d flags: %u\n",
	   info->pidfe->id, info->pidfe->nspid, info->pidfe->flags);
	return -1;
}

static struct file_desc_ops pidfd_desc_ops = {
	.type = FD_TYPES__PIDFD,
	.open = open_one_pidfd
};

static int collect_one_pidfd(void *obj, ProtobufCMessage *msg, struct cr_img *i)
{
	struct dead_pidfd *dead;
	struct pidfd_info *info = obj;

	info->pidfe = pb_msg(msg, PidfdEntry);
	pr_info_pidfd("Collected ", info->pidfe);

	info->dead = NULL;
	if (info->pidfe->nspid != -1)
		goto out;

	/*
	 * A zero ino is not an identity: the ino: line of /proc/pid/fdinfo/N
	 * is not required to be there, and taking its absence for a shared one
	 * would collapse unrelated dead processes onto a single stand-in. Such
	 * an entry is neither looked up nor hashed, so it gets a group, a
	 * creator and a stand-in all of its own.
	 */
	dead = info->pidfe->ino ? lookup_dead_pidfd(info->pidfe->ino) : NULL;
	if (!dead) {
		dead = xmalloc(sizeof(*dead));
		if (!dead) {
			pr_err("Could not allocate memory..\n");
			return -1;
		}

		dead->dead_pid_idx = dead_pid_add(info->pidfe->ino, info->pidfe->ino != 0, info->pidfe->attr);
		if (dead->dead_pid_idx < 0) {
			xfree(dead);
			return -1;
		}

		INIT_HLIST_NODE(&dead->hash);
		dead->list = NULL;
		dead->ino = info->pidfe->ino;
		dead->creator_id = info->pidfe->id;
		if (dead->ino)
			hlist_add_head(&dead->hash, &dead_pidfd_hash[dead->ino % DEAD_PIDFD_HASH_SIZE]);
	}

	info->dead = dead;
	info->next = dead->list;
	dead->list = info;
	if (dead->creator_id > info->pidfe->id)
		dead->creator_id = info->pidfe->id;

out:
	return file_desc_add(&info->d, info->pidfe->id, &pidfd_desc_ops);
}

struct collect_image_info pidfd_cinfo = {
	.fd_type = CR_FD_PIDFD,
	.pb_type = PB_PIDFD,
	.priv_size = sizeof(struct pidfd_info),
	.collect = collect_one_pidfd,
};
