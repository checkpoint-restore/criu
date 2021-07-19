#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <string.h>
#include <linux/msg.h>
#include <linux/sem.h>
#include <linux/shm.h>
#include <fcntl.h>
#include <limits.h>

#include "zdtmtst.h"

#define CLONE_NEWIPC 0x08000000

extern int msgctl(int __msqid, int __cmd, struct msqid_ds *__buf);
extern int semctl(int __semid, int __semnum, int __cmd, ...);
extern int shmctl(int __shmid, int __cmd, struct shmid_ds *__buf);

struct ipc_ids {
	int in_use; /* TODO: Check for 0 */
	//	unsigned short seq;
	//	unsigned short seq_max;
	//	struct rw_semaphore rw_mutex;
	//	struct idr ipcs_idr;		/* TODO */
};

struct ipc_ns {
	struct ipc_ids ids[3];

	int sem_ctls[4]; // +
	int used_sems; // +

	int msg_ctlmax; // +
	int msg_ctlmnb; // +
	int msg_ctlmni; // +
	int msg_bytes; // +
	int msg_hdrs; // +
	int auto_msgmni; // +
	int msg_next_id; // +
	int sem_next_id; // +
	int shm_next_id; // +

	size_t shm_ctlmax;
	size_t shm_ctlall;
	int shm_ctlmni;
	int shm_tot;
	int shm_rmid_forced;

	//	struct vfsmount	*mq_mnt;

	//	unsigned int    mq_queues_count;

	unsigned int mq_queues_max; /* initialized to DFLT_QUEUESMAX */
	unsigned int mq_msg_max; /* initialized to DFLT_MSGMAX */
	unsigned int mq_msgsize_max; /* initialized to DFLT_MSGSIZEMAX */
	unsigned int mq_msg_default; /* initialized to DFLT_MSG */
	unsigned int mq_msgsize_default; /* initialized to DFLT_MSGSIZE */

	struct user_ns *user_ns;
};

#define IPC_SEM_IDS 0
#define IPC_MSG_IDS 1
#define IPC_SHM_IDS 2

const char *test_doc = "Check that ipc ns context migrated successfully";
const char *test_author = "Stanislav Kinsbursky <skinsbursky@parallels.com>";

struct ipc_ns ipc_before, ipc_after;

static int read_ipc_sysctl(char *name, int *data, size_t size)
{
	int fd;
	int ret;
	char buf[32];

	fd = open(name, O_RDONLY);
	if (fd < 0) {
		pr_perror("Can't open %s", name);
		return fd;
	}
	ret = read(fd, buf, 32);
	if (ret < 0) {
		pr_perror("Can't read %s", name);
		ret = -errno;
		goto err;
	}
	*data = (int)strtoul(buf, NULL, 10);
	ret = 0;
err:
	close(fd);
	return ret;
}

static int get_messages_info(struct ipc_ns *ipc)
{
	struct msginfo info;
	int ret;

	ret = msgctl(0, MSG_INFO, (struct msqid_ds *)&info);
	if (ret < 0) {
		pr_perror("msgctl failed");
		return ret;
	}

	ipc->msg_ctlmax = info.msgmax;
	ipc->msg_ctlmnb = info.msgmnb;
	ipc->msg_ctlmni = info.msgmni;
	ipc->msg_bytes = info.msgtql;
	ipc->msg_hdrs = info.msgmap;
	ipc->ids[IPC_MSG_IDS].in_use = info.msgpool;

	if (read_ipc_sysctl("/proc/sys/kernel/auto_msgmni", &ipc->auto_msgmni, sizeof(ipc->auto_msgmni)))
		return -1;
	if (read_ipc_sysctl("/proc/sys/kernel/msg_next_id", &ipc->msg_next_id, sizeof(ipc->msg_next_id)))
		return -1;
	if (read_ipc_sysctl("/proc/sys/kernel/sem_next_id", &ipc->sem_next_id, sizeof(ipc->sem_next_id)))
		return -1;
	if (read_ipc_sysctl("/proc/sys/kernel/shm_next_id", &ipc->shm_next_id, sizeof(ipc->shm_next_id)))
		return -1;
	if (read_ipc_sysctl("/proc/sys/fs/mqueue/queues_max", (int *)&ipc->mq_queues_max, sizeof(ipc->mq_queues_max)))
		return -1;
	if (read_ipc_sysctl("/proc/sys/fs/mqueue/msg_max", (int *)&ipc->mq_msg_max, sizeof(ipc->mq_msg_max)))
		return -1;
	if (read_ipc_sysctl("/proc/sys/fs/mqueue/msgsize_max", (int *)&ipc->mq_msgsize_max,
			    sizeof(ipc->mq_msgsize_max)))
		return -1;
	if (read_ipc_sysctl("/proc/sys/fs/mqueue/msg_default", (int *)&ipc->mq_msg_default,
			    sizeof(ipc->mq_msg_default)))
		return -1;
	if (read_ipc_sysctl("/proc/sys/fs/mqueue/msgsize_default", (int *)&ipc->mq_msgsize_default,
			    sizeof(ipc->mq_msgsize_default)))
		return -1;

	return 0;
}

static int get_semaphores_info(struct ipc_ns *ipc)
{
	int err;
	struct seminfo info;

	err = semctl(0, 0, SEM_INFO, &info);
	if (err < 0)
		pr_perror("semctl failed");

	ipc->sem_ctls[0] = info.semmsl;
	ipc->sem_ctls[1] = info.semmns;
	ipc->sem_ctls[2] = info.semopm;
	ipc->sem_ctls[3] = info.semmni;
	ipc->used_sems = info.semaem;
	ipc->ids[IPC_SEM_IDS].in_use = info.semusz;

	return 0;
}

static int get_shared_memory_info(struct ipc_ns *ipc)
{
	int ret;
	union {
		struct shminfo64 shminfo64;
		struct shm_info shminfo;
		struct shmid_ds shmid;
	} u;

	ret = shmctl(0, IPC_INFO, &u.shmid);
	if (ret < 0)
		pr_perror("semctl failed");

	ipc->shm_ctlmax = u.shminfo64.shmmax;
	ipc->shm_ctlall = u.shminfo64.shmall;
	ipc->shm_ctlmni = u.shminfo64.shmmni;

	ret = shmctl(0, SHM_INFO, &u.shmid);
	if (ret < 0)
		pr_perror("semctl failed");

	ipc->shm_tot = u.shminfo.shm_tot;
	ipc->ids[IPC_SHM_IDS].in_use = u.shminfo.used_ids;

	if (read_ipc_sysctl("/proc/sys/kernel/shm_rmid_forced", &ipc->shm_rmid_forced, sizeof(ipc->shm_rmid_forced)))
		return -1;

	return 0;
}

int fill_ipc_ns(struct ipc_ns *ipc)
{
	int ret;

	ret = get_messages_info(ipc);
	if (ret < 0) {
		pr_err("Failed to collect messages\n");
		return ret;
	}

	ret = get_semaphores_info(ipc);
	if (ret < 0) {
		pr_err("Failed to collect semaphores\n");
		return ret;
	}

	ret = get_shared_memory_info(ipc);
	if (ret < 0) {
		pr_err("Failed to collect shared memory\n");
		return ret;
	}
	return 0;
}

static int rand_ipc_sysctl(char *name, unsigned int val)
{
	int fd;
	int ret;
	char buf[32];

	fd = open(name, O_WRONLY);
	if (fd < 0) {
		pr_perror("Can't open %s", name);
		return fd;
	}
	sprintf(buf, "%d\n", val);
	ret = write(fd, buf, strlen(buf));
	if (ret < 0) {
		pr_perror("Can't write %u into %s", val, name);
		return -errno;
	}
	close(fd);
	return 0;
}

#define MAX_MNI (1 << 15)

static int rand_ipc_sem(void)
{
	int fd;
	int ret;
	char buf[128];
	char *name = "/proc/sys/kernel/sem";

	fd = open(name, O_WRONLY);
	if (fd < 0) {
		pr_perror("Can't open %s", name);
		return fd;
	}
	sprintf(buf, "%d %d %d %d\n", (unsigned)lrand48(), (unsigned)lrand48(), (unsigned)lrand48(),
		(unsigned)lrand48() % MAX_MNI);
	ret = write(fd, buf, 128);
	if (ret < 0) {
		pr_perror("Can't write %s", name);
		return -errno;
	}
	close(fd);
	return 0;
}

static int rand_ipc_ns(void)
{
	int ret;

	ret = rand_ipc_sem();
	if (!ret)
		ret = rand_ipc_sysctl("/proc/sys/kernel/msgmax", (unsigned)lrand48());
	if (!ret)
		ret = rand_ipc_sysctl("/proc/sys/kernel/msgmnb", (unsigned)lrand48());
	if (!ret)
		ret = rand_ipc_sysctl("/proc/sys/kernel/msgmni", (unsigned)lrand48() % MAX_MNI);
	if (!ret)
		ret = rand_ipc_sysctl("/proc/sys/kernel/auto_msgmni", 0);
	if (!ret && (unsigned)lrand48() % 2)
		ret = rand_ipc_sysctl("/proc/sys/kernel/msg_next_id", (unsigned)lrand48() % ((unsigned)INT_MAX + 1));
	if (!ret && (unsigned)lrand48() % 2)
		ret = rand_ipc_sysctl("/proc/sys/kernel/sem_next_id", (unsigned)lrand48() % ((unsigned)INT_MAX + 1));
	if (!ret && (unsigned)lrand48() % 2)
		ret = rand_ipc_sysctl("/proc/sys/kernel/shm_next_id", (unsigned)lrand48() % ((unsigned)INT_MAX + 1));
	if (!ret)
		ret = rand_ipc_sysctl("/proc/sys/kernel/shmmax", (unsigned)lrand48());
	if (!ret)
		ret = rand_ipc_sysctl("/proc/sys/kernel/shmall", (unsigned)lrand48());
	if (!ret)
		ret = rand_ipc_sysctl("/proc/sys/kernel/shmmni", (unsigned)lrand48() % MAX_MNI);
	if (!ret)
		ret = rand_ipc_sysctl("/proc/sys/kernel/shm_rmid_forced", (unsigned)lrand48() & 1);

	if (!ret)
		ret = rand_ipc_sysctl("/proc/sys/fs/mqueue/queues_max", (((unsigned)lrand48()) % 1023) + 1);
	if (!ret)
		ret = rand_ipc_sysctl("/proc/sys/fs/mqueue/msg_max", ((unsigned)lrand48() % 65536) + 1);
	if (!ret)
		ret = rand_ipc_sysctl("/proc/sys/fs/mqueue/msgsize_max",
				      ((unsigned)lrand48() & (8192 * 128 - 1)) | 128);
	if (!ret)
		ret = rand_ipc_sysctl("/proc/sys/fs/mqueue/msg_default", ((unsigned)lrand48() % 65536) + 1);
	if (!ret)
		ret = rand_ipc_sysctl("/proc/sys/fs/mqueue/msgsize_default",
				      ((unsigned)lrand48() & (8192 * 128 - 1)) | 128);

	if (ret < 0)
		pr_err("Failed to randomize ipc namespace tunables\n");

	return ret;
}

static void show_ipc_entry(struct ipc_ns *old, struct ipc_ns *new)
{
	int i;

	for (i = 0; i < 3; i++) {
		if (old->ids[i].in_use != new->ids[i].in_use)
			pr_err("ids[%d].in_use differs: %d ---> %d\n", i, old->ids[i].in_use, new->ids[i].in_use);
	}
	for (i = 0; i < 4; i++) {
		if (old->sem_ctls[i] != new->sem_ctls[i])
			pr_err("sem_ctls[%d] differs: %d ---> %d\n", i, old->sem_ctls[i], new->sem_ctls[i]);
	}

	if (old->msg_ctlmax != new->msg_ctlmax)
		pr_err("msg_ctlmax differs: %d ---> %d\n", old->msg_ctlmax, new->msg_ctlmax);
	if (old->msg_ctlmnb != new->msg_ctlmnb)
		pr_err("msg_ctlmnb differs: %d ---> %d\n", old->msg_ctlmnb, new->msg_ctlmnb);
	if (old->msg_ctlmni != new->msg_ctlmni)
		pr_err("msg_ctlmni differs: %d ---> %d\n", old->msg_ctlmni, new->msg_ctlmni);
	if (old->auto_msgmni != new->auto_msgmni)
		pr_err("auto_msgmni differs: %d ---> %d\n", old->auto_msgmni, new->auto_msgmni);
	if (old->msg_next_id != new->msg_next_id)
		pr_err("msg_next_id differs: %d ---> %d\n", old->msg_next_id, new->msg_next_id);
	if (old->sem_next_id != new->sem_next_id)
		pr_err("sem_next_id differs: %d ---> %d\n", old->sem_next_id, new->sem_next_id);
	if (old->shm_next_id != new->shm_next_id)
		pr_err("shm_next_id differs: %d ---> %d\n", old->shm_next_id, new->shm_next_id);
	if (old->shm_ctlmax != new->shm_ctlmax)
		pr_err("shm_ctlmax differs: %zu ---> %zu\n", old->shm_ctlmax, new->shm_ctlmax);
	if (old->shm_ctlall != new->shm_ctlall)
		pr_err("shm_ctlall differs: %zu ---> %zu\n", old->shm_ctlall, new->shm_ctlall);
	if (old->shm_ctlmni != new->shm_ctlmni)
		pr_err("shm_ctlmni differs: %d ---> %d\n", old->shm_ctlmni, new->shm_ctlmni);
	if (old->shm_rmid_forced != new->shm_rmid_forced)
		pr_err("shm_rmid_forced differs: %d ---> %d\n", old->shm_rmid_forced, new->shm_rmid_forced);
	if (old->mq_queues_max != new->mq_queues_max)
		pr_err("mq_queues_max differs: %d ---> %d\n", old->mq_queues_max, new->mq_queues_max);
	if (old->mq_msg_max != new->mq_msg_max)
		pr_err("mq_msg_max differs: %d ---> %d\n", old->mq_msg_max, new->mq_msg_max);
	if (old->mq_msgsize_max != new->mq_msgsize_max)
		pr_err("mq_msgsize_max differs: %d ---> %d\n", old->mq_msgsize_max, new->mq_msgsize_max);
	if (old->mq_msg_default != new->mq_msg_default)
		pr_err("mq_msg_default differs: %d ---> %d\n", old->mq_msg_default, new->mq_msg_default);
	if (old->mq_msgsize_default != new->mq_msgsize_default)
		pr_err("mq_msgsize_default differs: %d ---> %d\n", old->mq_msgsize_default, new->mq_msgsize_default);
}

int main(int argc, char **argv)
{
	int ret;

	test_init(argc, argv);

	ret = rand_ipc_ns();
	if (ret) {
		pr_err("Failed to randomize ipc ns before migration\n");
		return -1;
	}

	ret = fill_ipc_ns(&ipc_before);
	if (ret) {
		pr_err("Failed to collect ipc ns before migration\n");
		return ret;
	}

	test_daemon();
	test_waitsig();

	ret = fill_ipc_ns(&ipc_after);
	if (ret) {
		pr_err("Failed to collect ipc ns after migration\n");
		return ret;
	}

	if (memcmp(&ipc_before, &ipc_after, sizeof(ipc_after))) {
		pr_err("IPCs differ\n");
		show_ipc_entry(&ipc_before, &ipc_after);
		return -EINVAL;
	}

	pass();
	return 0;
}
