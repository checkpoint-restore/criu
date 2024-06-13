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

#undef LOG_PREFIX
#define LOG_PREFIX "pidfd: "

#ifndef PIDFD_THREAD
#define PIDFD_THREAD O_EXCL
#endif

struct pidfd_info {
	PidfdEntry *pidfe;
	struct file_desc d;
};

struct dead_pidfd {
	unsigned int ino;
	int pid;
	size_t count;
	mutex_t pidfd_lock;
	struct hlist_node hash;
};

#define DEAD_PIDFD_HASH_SIZE 32
static struct hlist_head dead_pidfd_hash[DEAD_PIDFD_HASH_SIZE];
static mutex_t *dead_pidfd_hash_lock;

int init_dead_pidfd_hash(void)
{
	for (int i = 0; i < DEAD_PIDFD_HASH_SIZE; i++)
		INIT_HLIST_HEAD(&dead_pidfd_hash[i]);

	dead_pidfd_hash_lock = shmalloc(sizeof(*dead_pidfd_hash_lock));
	if (!dead_pidfd_hash_lock)
		return -1;

	mutex_init(dead_pidfd_hash_lock);

	return 0;
}

static struct dead_pidfd *lookup_dead_pidfd(unsigned int ino)
{
	struct dead_pidfd *dead;
	struct hlist_head *chain;

	mutex_lock(dead_pidfd_hash_lock);
	chain = &dead_pidfd_hash[ino % DEAD_PIDFD_HASH_SIZE];
	hlist_for_each_entry(dead, chain, hash) {
		if (dead->ino == ino) {
			mutex_unlock(dead_pidfd_hash_lock);
			return dead;
		}
	}
	mutex_unlock(dead_pidfd_hash_lock);

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

static int free_dead_pidfd(struct dead_pidfd *dead)
{
	int status;

	if (kill(dead->pid, SIGKILL) < 0) {
		pr_perror("Could not kill temporary process with pid: %d",
		dead->pid);
		goto err;
	}

	if (waitpid(dead->pid, &status, 0) != dead->pid) {
		pr_perror("Could not wait on temporary process with pid: %d",
		dead->pid);
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

	mutex_lock(dead_pidfd_hash_lock);
	hlist_del(&dead->hash);
	mutex_unlock(dead_pidfd_hash_lock);
	return 0;
err:
	return -1;
}

static int open_one_pidfd(struct file_desc *d, int *new_fd)
{
	struct pidfd_info *info;
	struct dead_pidfd *dead = NULL;
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

	mutex_lock(&dead->pidfd_lock);
	BUG_ON(dead->count == 0);
	dead->count--;
	if (dead->pid == -1) {
		dead->pid = create_tmp_process();
		if (dead->pid < 0) {
			mutex_unlock(&dead->pidfd_lock);
			goto err_close;
		}
	}

	pidfd = pidfd_open(dead->pid, info->pidfe->flags);
	if (pidfd < 0) {
		pr_perror("Could not open pidfd for %d", info->pidfe->nspid);
		mutex_unlock(&dead->pidfd_lock);
		goto err_close;
	}

	if (dead->count == 0) {
		if (free_dead_pidfd(dead)) {
			pr_err("Failed to delete dead_pidfd struct\n");
			mutex_unlock(&dead->pidfd_lock);
			close(pidfd);
			goto err_close;
		}
	}
	mutex_unlock(&dead->pidfd_lock);

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

	if (info->pidfe->nspid != -1)
		goto out;

	dead = lookup_dead_pidfd(info->pidfe->ino);
	if (dead) {
		mutex_lock(&dead->pidfd_lock);
		dead->count++;
		mutex_unlock(&dead->pidfd_lock);
		goto out;
	}

	dead = shmalloc(sizeof(*dead));
	if (!dead) {
		pr_err("Could not allocate shared memory..\n");
		return -1;
	}

	INIT_HLIST_NODE(&dead->hash);
	dead->ino = info->pidfe->ino;
	dead->count = 1;
	dead->pid = -1;
	mutex_init(&dead->pidfd_lock);

	mutex_lock(dead_pidfd_hash_lock);
	hlist_add_head(&dead->hash, &dead_pidfd_hash[dead->ino % DEAD_PIDFD_HASH_SIZE]);
	mutex_unlock(dead_pidfd_hash_lock);
out:
	return file_desc_add(&info->d, info->pidfe->id, &pidfd_desc_ops);
}

struct collect_image_info pidfd_cinfo = {
	.fd_type = CR_FD_PIDFD,
	.pb_type = PB_PIDFD,
	.priv_size = sizeof(struct pidfd_info),
	.collect = collect_one_pidfd,
};
