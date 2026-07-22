#include "common/lock.h"
#include "imgset.h"
#include "kerndat.h"
#include "pidfd.h"
#include "fdinfo.h"
#include "pidfd.pb-c.h"
#include "protobuf.h"
#include "pstree.h"
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <signal.h>
#include "common/bug.h"
#include "common/compiler.h"
#include "rst-malloc.h"

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
	unsigned int ino;
	int creator_id;

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

static struct dead_pidfd *lookup_dead_pidfd(unsigned int ino)
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
	pr_info("%s: id %#08x flags %u NSpid %d ino %u\n",
		action, pidfe->id, pidfe->flags, pidfe->nspid, pidfe->ino
	);
}

static int dump_one_pidfd(int pidfd, u32 id, const struct fd_parms *p)
{
	struct pidfd_dump_info pidfd_info = {.pidfe = PIDFD_ENTRY__INIT};
	PidfsAttrEntry attr = PIDFS_ATTR_ENTRY__INIT;
	FileEntry fe = FILE_ENTRY__INIT;
	int exit_code;

	if (parse_fdinfo(pidfd, FD_TYPES__PIDFD, &pidfd_info))
		return -1;

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
		while(1)
			sleep(1);
	}
	return tmp_process;
}

/*
 * A restore-time stand-in for a process that was already dead at dump time.
 * @wfd is the write end of the pipe a status helper blocks on; it is -1 when
 * the original exit status is unknown and a plain SIGKILL is the best we can
 * reproduce.
 */
struct dead_pid {
	struct dead_pid *next;
	pid_t pid;
	int wfd;
	bool has_status;
	int status;
};

/*
 * Fork a helper that blocks until we tell it how to die, then reproduces an
 * arbitrary wait(2) status: it exits with a given code or raises a given
 * signal. This is how a stand-in for a dead pid gets the exit status the
 * process it stands in for had. *wfd is the write end of a pipe; write a
 * wait-status word to it (see kill_status_helper()) to make the child die.
 */
static int create_status_helper(struct dead_pid_pool *pool, int *wfd)
{
	int pipefd[2];
	pid_t pid;

	if (pipe(pipefd) < 0) {
		pr_perror("Could not create pipe for status helper");
		return -1;
	}

	pid = fork();
	if (pid < 0) {
		pr_perror("Could not fork status helper");
		close(pipefd[0]);
		close(pipefd[1]);
		return -1;
	}

	if (pid == 0) {
		struct dead_pid *dp;
		int status = 0;
		ssize_t n;

		close(pipefd[1]);
		/*
		 * Drop the write ends of the helpers forked before us, so that
		 * each one only ever sees EOF from its own pipe. Otherwise a
		 * criu that dies before kill_status_helper() would leave them
		 * all blocked on a read that can never complete.
		 */
		for (dp = pool->list; dp; dp = dp->next) {
			if (dp->wfd >= 0)
				close(dp->wfd);
		}

		n = read(pipefd[0], &status, sizeof(status));
		if (n != sizeof(status))
			_exit(1);

		if (WIFEXITED(status)) {
			_exit(WEXITSTATUS(status));
		} else if (WIFSIGNALED(status)) {
			int sig = WTERMSIG(status);
			sigset_t unblock;

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

	close(pipefd[0]);
	*wfd = pipefd[1];
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
static int kill_status_helper(pid_t pid, int wfd, int status)
{
	sigset_t oldmask;
	int wstatus;
	int ret = -1;
	bool blocked = false, reaped = false;

	if (helper_block_sigchld(&oldmask))
		goto out;
	blocked = true;

	if (write(wfd, &status, sizeof(status)) != sizeof(status)) {
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
	}

	ret = 0;
out:
	close(wfd);
	/*
	 * On the error paths the child may still be running -- blocked on the
	 * pipe we just closed, or never signalled at all. Kill and reap it so
	 * we neither leak a zombie nor leave SIGCHLD blocked in the caller.
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

/*
 * Return the pid of a stand-in process for a dead struct pid with the given
 * pidfs attributes; fork one if @pool has none matching yet. @attr may be
 * NULL, or carry no exit code, when the way the process died is not known.
 */
pid_t dead_pid_get(struct dead_pid_pool *pool, PidfsAttrEntry *attr)
{
	bool has_status = attr && attr->has_exit_code;
	int status = has_status ? attr->exit_code : 0;
	struct dead_pid *dp;
	int wfd = -1;
	pid_t pid;

	for (dp = pool->list; dp; dp = dp->next) {
		if (dp->has_status != has_status)
			continue;
		if (!has_status || dp->status == status)
			return dp->pid;
	}

	if (has_status)
		pid = create_status_helper(pool, &wfd);
	else
		pid = create_tmp_process();
	if (pid < 0)
		return -1;

	dp = xmalloc(sizeof(*dp));
	if (!dp) {
		/*
		 * Kill before closing: a status helper is blocked reading the
		 * pipe, so closing it first would race the SIGKILL with the
		 * child exiting on its own.
		 */
		kill_helper(pid);
		if (wfd >= 0)
			close(wfd);
		return -1;
	}

	dp->pid = pid;
	dp->wfd = wfd;
	dp->has_status = has_status;
	dp->status = status;
	dp->next = pool->list;
	pool->list = dp;

	return pid;
}

/*
 * Make every stand-in in @pool die the way the process it stands in for did,
 * and reap it. Call this only once everything that needs to reference these
 * dead pids has done so: each reference -- an open pidfd, an skb holding the
 * struct pid -- keeps the pid around, so it goes stale exactly as it was
 * before the dump.
 */
int dead_pid_put_all(struct dead_pid_pool *pool)
{
	struct dead_pid *dp, *next;
	int ret = 0;

	for (dp = pool->list; dp; dp = next) {
		next = dp->next;
		if (dp->has_status) {
			if (kill_status_helper(dp->pid, dp->wfd, dp->status))
				ret = -1;
		} else if (kill_helper(dp->pid)) {
			ret = -1;
		}
		xfree(dp);
	}
	pool->list = NULL;

	return ret;
}

static int open_one_pidfd(struct file_desc *d, int *new_fd)
{
	struct pidfd_info *info, *child;
	struct dead_pidfd *dead = NULL;
	struct dead_pid_pool pool = {};
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

	dead = lookup_dead_pidfd(info->pidfe->ino);
	BUG_ON(!dead);

	if (info->dead && info->dead->creator_id != info->pidfe->id) {
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
	 * in for it with a process that dies the way the original did once
	 * every pidfd referring to it has been opened.
	 *
	 * All the pidfds handled here refer to that one struct pid, so the pool
	 * only ever holds a single stand-in. It is a pool because sk-queue.c
	 * restores many dead pids at once and shares the same helpers for it.
	 */
	pid = dead_pid_get(&pool, info->pidfe->attr);
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
	if (dead_pid_put_all(&pool))
		goto err_close;
out:
	if (rst_file_params(pidfd, info->pidfe->fown, info->pidfe->flags)) {
		goto err_close;
	}

	*new_fd = pidfd;
	return 0;
err_close:
	if (pidfd >= 0)
		close(pidfd);
	dead_pid_put_all(&pool);
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

	dead = lookup_dead_pidfd(info->pidfe->ino);
	if (!dead) {
		dead = xmalloc(sizeof(*dead));
		if (!dead) {
			pr_err("Could not allocate memory..\n");
			return -1;
		}

		INIT_HLIST_NODE(&dead->hash);
		dead->list = NULL;
		dead->ino = info->pidfe->ino;
		dead->creator_id = info->pidfe->id;
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
