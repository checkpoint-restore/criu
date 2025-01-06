#include "common/lock.h"
#include "imgset.h"
#include "pidfd.h"
#include "fdinfo.h"
#include "pidfd.pb-c.h"
#include "protobuf.h"
#include "pstree.h"
#include <stdlib.h>
#include <sys/wait.h>
#include <signal.h>
#include "common/bug.h"
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
	FileEntry fe = FILE_ENTRY__INIT;

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

static int kill_helper(pid_t pid)
{
	int status;
	sigset_t blockmask, oldmask;

	/*
	 * Block SIGCHLD to prevent interfering from sigchld_handler()
	 * and to properly handle the tmp process termination without
	 * a race condition. A similar approach is used in cr_system().
	 */
	sigemptyset(&oldmask);
	sigemptyset(&blockmask);
	sigaddset(&blockmask, SIGCHLD);
	if (sigprocmask(SIG_BLOCK, &blockmask, &oldmask) == -1) {
		pr_perror("Cannot set mask of blocked signals");
		goto err;
	}

	if (kill(pid, SIGKILL) < 0) {
		pr_perror("Could not kill temporary process with pid: %d", pid);
		goto err;
	}

	if (waitpid(pid, &status, 0) != pid) {
		pr_perror("Could not wait on temporary process with pid: %d", pid);
		goto err;
	}

	/* Restore the original signal mask after tmp process has terminated */
	if (sigprocmask(SIG_SETMASK, &oldmask, NULL) == -1) {
		pr_perror("Cannot clear blocked signals");
		goto err;
	}

	if (!WIFSIGNALED(status)) {
		pr_err("Expected temporary process to be terminated by a signal\n");
		goto err;
	}

	if (WTERMSIG(status) != SIGKILL) {
		pr_err("Expected temporary process to be terminated by SIGKILL\n");
		goto err;
	}

	return 0;
err:
	return -1;
}

static int open_one_pidfd(struct file_desc *d, int *new_fd)
{
	struct pidfd_info *info, *child;
	struct dead_pidfd *dead = NULL;
	pid_t pid;
	int pidfd;

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

	pid = create_tmp_process();
	if (pid < 0)
		goto err_close;

	for (child = dead->list; child; child = child->next) {
		if (child == info)
			continue;
		pidfd = pidfd_open(pid, child->pidfe->flags);
		if (pidfd < 0) {
			pr_perror("Could not open pidfd for %d", child->pidfe->nspid);
			goto err_close;
		}

		if (send_desc_to_peer(pidfd, &child->d)) {
			pr_perror("Can't send file descriptor");
			close(pidfd);
			return -1;
		}
		close(pidfd);
	}

	pidfd = pidfd_open(pid, info->pidfe->flags);
	if (pidfd < 0) {
		pr_perror("Could not open pidfd for %d", info->pidfe->nspid);
		goto err_close;
	}
	if (kill_helper(pid))
		goto err_close;
out:
	if (rst_file_params(pidfd, info->pidfe->fown, info->pidfe->flags)) {
		goto err_close;
	}

	*new_fd = pidfd;
	return 0;
err_close:
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
