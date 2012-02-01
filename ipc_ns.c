#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <sys/msg.h>
#include <sys/sem.h>
#include <sys/shm.h>
#include "util.h"
#include "crtools.h"
#include "syscall.h"
#include "namespaces.h"

struct ipc_ns_data {
	struct ipc_ns_entry entry;
};

#define IPC_SEM_IDS		0
#define IPC_MSG_IDS		1
#define IPC_SHM_IDS		2

static int collect_ipc_msg(void *data)
{
	struct msginfo info;
	int ret;
	int fd;

	ret = msgctl(0, MSG_INFO, (struct msqid_ds *)&info);
	if (ret < 0) {
		pr_perror("msgctl failed");
		return ret;
	}

	if (ret) {
		pr_err("IPC messages migration is not supported yet\n");
		return -EINVAL;
	}

	return 0;
}

static int collect_ipc_sem(void *data)
{
	int ret;
	struct seminfo info;

	ret = semctl(0, 0, SEM_INFO, &info);
	if (ret < 0)
		pr_perror("semctl failed");

	if (ret) {
		pr_err("IPC semaphores migration is not supported yet\n");
		return -EINVAL;
	}

	return 0;
}

static int collect_ipc_shm(void *data)
{
	int fd;
	int ret;
	struct shmid_ds shmid;

	ret = shmctl(0, IPC_INFO, &shmid);
	if (ret < 0)
		pr_perror("semctl failed");

	if (ret) {
		pr_err("IPC shared memory migration is not supported yet\n");
		return -EINVAL;
	}

	return 0;
}

#ifdef CONFIG_X86_64
static int read_ipc_sysctl_long(char *name, u64 *data, size_t size)
{
	int fd;
	int ret;
	char buf[32];

	fd = open(name, O_RDONLY);
	if (fd < 0) {
		pr_perror("Can't open %s", name);
		return fd;
	}
	ret = read(fd, buf, sizeof(buf));
	if (ret < 0) {
		pr_perror("Can't read %s", name);
		ret = -errno;
		goto err;
	}
	*data = strtoull(buf, NULL, 10);
err:
	close(fd);
	return ret;
}
#endif

static int read_ipc_sysctl(char *name, u32 *data, size_t size)
{
	int fd;
	int ret;
	char buf[32];

	fd = open(name, O_RDONLY);
	if (fd < 0) {
		pr_perror("Can't open %s", name);
		return fd;
	}
	ret = read(fd, buf, sizeof(buf));
	if (ret < 0) {
		pr_perror("Can't read %s", name);
		ret = -errno;
		goto err;
	}
	*data = (u32)strtoul(buf, NULL, 10);
err:
	close(fd);
	return ret;
}

static int read_ipc_sem(u32 sem[])
{
	int fd;
	int ret;
	char buf[128], *ptr = buf;
	char *name = "/proc/sys/kernel/sem";
	int i;

	fd = open(name, O_RDONLY);
	if (fd < 0) {
		pr_perror("Can't open %s", name);
		return fd;
	}
	ret = read(fd, buf, sizeof(buf));
	if (ret < 0) {
		pr_perror("Can't read %s", name);
		ret = -errno;
		goto err;
	}
	sem[0] = (u32)strtoul(ptr, &ptr, 10); ptr++;
	sem[1] = (u32)strtoul(ptr, &ptr, 10); ptr++;
	sem[2] = (u32)strtoul(ptr, &ptr, 10); ptr++;
	sem[3] = (u32)strtoul(ptr, &ptr, 10); ptr++;
err:
	close(fd);
	return ret;
}

static int collect_ipc_tun(struct ipc_ns_entry *entry)
{
	int ret;

	ret = read_ipc_sem(entry->sem_ctls);
	if (ret < 0)
		goto err;
	ret = read_ipc_sysctl("/proc/sys/kernel/msgmax",
			  &entry->msg_ctlmax, sizeof(entry->msg_ctlmax));
	if (ret < 0)
		goto err;
	ret = read_ipc_sysctl("/proc/sys/kernel/msgmnb",
			  &entry->msg_ctlmnb, sizeof(entry->msg_ctlmnb));
	if (ret < 0)
		goto err;
	ret = read_ipc_sysctl("/proc/sys/kernel/msgmni",
			  &entry->msg_ctlmni, sizeof(entry->msg_ctlmni));
	if (ret < 0)
		goto err;
	ret = read_ipc_sysctl("/proc/sys/kernel/auto_msgmni",
			  &entry->auto_msgmni, sizeof(entry->auto_msgmni));
	if (ret < 0)
		goto err;
#ifdef CONFIG_X86_64
	ret = read_ipc_sysctl_long("/proc/sys/kernel/shmmax",
			  (u64 *)entry->shm_ctlmax, sizeof(entry->shm_ctlmax));
	if (ret < 0)
		goto err;
	ret = read_ipc_sysctl_long("/proc/sys/kernel/shmall",
			  (u64 *)entry->shm_ctlall, sizeof(entry->shm_ctlall));
#else
	ret = read_ipc_sysctl("/proc/sys/kernel/shmmax",
			  entry->shm_ctlmax, sizeof(entry->shm_ctlmax));
	if (ret < 0)
		goto err;
	ret = read_ipc_sysctl("/proc/sys/kernel/shmall",
			  entry->shm_ctlall, sizeof(entry->shm_ctlall));
#endif
	if (ret < 0)
		goto err;
	ret = read_ipc_sysctl("/proc/sys/kernel/shmmni",
			  &entry->shm_ctlmni, sizeof(entry->shm_ctlmni));
	if (ret < 0)
		goto err;
	ret = read_ipc_sysctl("/proc/sys/kernel/shm_rmid_forced",
			  &entry->shm_rmid_forced, sizeof(entry->shm_rmid_forced));
	if (ret < 0)
		goto err;


	ret = read_ipc_sysctl("/proc/sys/fs/mqueue/queues_max",
			  &entry->mq_queues_max, sizeof(entry->mq_queues_max));
	if (ret < 0)
		goto err;
	ret = read_ipc_sysctl("/proc/sys/fs/mqueue/msg_max",
			  &entry->mq_msg_max, sizeof(entry->mq_msg_max));
	if (ret < 0)
		goto err;
	ret = read_ipc_sysctl("/proc/sys/fs/mqueue/msgsize_max",
			  &entry->mq_msgsize_max, sizeof(entry->mq_msgsize_max));
	if (ret < 0)
		goto err;

	return 0;
err:
	pr_err("Failed to dump ipc namespace tunables\n");
	return ret;
}

static int collect_ipc_data(int ns_pid, struct ipc_ns_data *ipc)
{
	int fd, ret;
	struct ipc_ns_entry *entry = &ipc->entry;

	ret = switch_ns(ns_pid, CLONE_NEWIPC, "ipc");
	if (ret < 0)
		return ret;

	entry->in_use[IPC_MSG_IDS] = ret = collect_ipc_msg(NULL);
	if (ret < 0)
		return ret;
	entry->in_use[IPC_SEM_IDS] = ret = collect_ipc_sem(NULL);
	if (ret < 0)
		return ret;
	entry->in_use[IPC_SHM_IDS] = ret = collect_ipc_shm(NULL);
	if (ret < 0)
		return ret;
	ret = collect_ipc_tun(entry);
	if (ret < 0)
		return ret;

	return 0;
}

static int dump_ipc_data(int fd, struct ipc_ns_data *ipc)
{
	int err;

	err = write_img_buf(fd, &ipc->entry, sizeof(ipc->entry));
	if (err < 0) {
		pr_err("Failed to write IPC namespace entry\n");
		return err;
	}
	return 0;
}

int dump_ipc_ns(int ns_pid, struct cr_fdset *fdset)
{
	int fd, ret;
	struct ipc_ns_data ipc;

	ret = collect_ipc_data(ns_pid, &ipc);
	if (ret < 0) {
		pr_err("Failed to collect IPC namespace data\n");
		return ret;
	}

	ret = dump_ipc_data(fdset->fds[CR_FD_IPCNS], &ipc);
	if (ret < 0) {
		pr_err("Failed to write IPC namespace data\n");
		return ret;
	}
	return 0;
}

static void show_ipc_entry(struct ipc_ns_entry *entry)
{
	pr_info("/proc/sys/kernel/sem             : %d\t%d\t%d\t%d\n",
				entry->sem_ctls[0], entry->sem_ctls[1],
				entry->sem_ctls[2], entry->sem_ctls[3]);
	pr_info("/proc/sys/kernel/msgmax          : %d\n", entry->msg_ctlmax);
	pr_info("/proc/sys/kernel/msgmnb          : %d\n", entry->msg_ctlmnb);
	pr_info("/proc/sys/kernel/msgmni          : %d\n", entry->msg_ctlmni);
	pr_info("/proc/sys/kernel/auto_msgmni     : %d\n", entry->auto_msgmni);
	pr_info("/proc/sys/kernel/shmmax          : %ld\n", *(u64 *)entry->shm_ctlmax);
	pr_info("/proc/sys/kernel/shmall          : %ld\n", *(u64 *)entry->shm_ctlall);
	pr_info("/proc/sys/kernel/shmmni          : %d\n", entry->shm_ctlmni);
	pr_info("/proc/sys/kernel/shm_rmid_forced : %d\n", entry->shm_rmid_forced);
	pr_info("/proc/sys/fs/mqueue/queues_max   : %d\n", entry->mq_queues_max);
	pr_info("/proc/sys/fs/mqueue/msg_max      : %d\n", entry->mq_msg_max);
	pr_info("/proc/sys/fs/mqueue/msgsize_max  : %d\n", entry->mq_msgsize_max);
}

static void show_ipc_data(int fd)
{
	int ret;
	struct ipc_ns_data ipc;

	ret = read_img(fd, &ipc);
	if (ret <= 0)
		return;
	show_ipc_entry(&ipc.entry);
}

void show_ipc_ns(int fd)
{
	pr_img_head(CR_FD_IPCNS);
	show_ipc_data(fd);
	pr_img_tail(CR_FD_IPCNS);
}

#ifdef CONFIG_X86_64
static int write_ipc_sysctl_long(char *name, u64 *data)
{
	int fd;
	int ret;
	char buf[32];

	fd = open(name, O_WRONLY);
	if (fd < 0) {
		pr_perror("Can't open %s", name);
		return fd;
	}
	sprintf(buf, "%ld\n", *(long *)data);
	ret = write(fd, buf, 32);
	if (ret < 0) {
		pr_perror("Can't write %s", name);
		ret = -errno;
	}
	close(fd);
	return ret;
}
#endif

static int write_ipc_sysctl(char *name, u32 *data)
{
	int fd;
	int ret;
	char buf[32];

	fd = open(name, O_WRONLY);
	if (fd < 0) {
		pr_perror("Can't open %s", name);
		return fd;
	}
	sprintf(buf, "%d\n", *(int *)data);
	ret = write(fd, buf, 32);
	if (ret < 0) {
		pr_perror("Can't write %s", name);
		ret = -errno;
	}
	close(fd);
	return ret;
}

static int write_ipc_sem(u32 sem[])
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
	sprintf(buf, "%d %d %d %d\n", sem[0], sem[1], sem[2], sem[3]);
	ret = write(fd, buf, 128);
	if (ret < 0) {
		pr_perror("Can't write %s", name);
		ret = -errno;
	}
	close(fd);
	return ret;
}

static int prepare_ipc_tun(struct ipc_ns_entry *entry)
{
	int ret;

	ret = write_ipc_sem(entry->sem_ctls);
	if (ret < 0)
		goto err;
	ret = write_ipc_sysctl("/proc/sys/kernel/msgmax", &entry->msg_ctlmax);
	if (ret < 0)
		goto err;
	ret = write_ipc_sysctl("/proc/sys/kernel/msgmnb", &entry->msg_ctlmnb);
	if (ret < 0)
		goto err;
	ret = write_ipc_sysctl("/proc/sys/kernel/msgmni", &entry->msg_ctlmni);
	if (ret < 0)
		goto err;
	ret = write_ipc_sysctl("/proc/sys/kernel/auto_msgmni", &entry->auto_msgmni);
	if (ret < 0)
		goto err;
#ifdef CONFIG_X86_64
	ret = write_ipc_sysctl_long("/proc/sys/kernel/shmmax", (u64 *)entry->shm_ctlmax);
	if (ret < 0)
		goto err;
	ret = write_ipc_sysctl_long("/proc/sys/kernel/shmall", (u64 *)entry->shm_ctlall);
#else
	ret = write_ipc_sysctl("/proc/sys/kernel/shmmax", entry->shm_ctlmax);
	if (ret < 0)
		goto err;
	ret = write_ipc_sysctl("/proc/sys/kernel/shmall", entry->shm_ctlall);
#endif
	if (ret < 0)
		goto err;
	ret = write_ipc_sysctl("/proc/sys/kernel/shmmni", &entry->shm_ctlmni);
	if (ret < 0)
		goto err;
	ret = write_ipc_sysctl("/proc/sys/kernel/shm_rmid_forced", &entry->shm_rmid_forced);
	if (ret < 0)
		goto err;


	ret = write_ipc_sysctl("/proc/sys/fs/mqueue/queues_max", &entry->mq_queues_max);
	if (ret < 0)
		goto err;
	ret = write_ipc_sysctl("/proc/sys/fs/mqueue/msg_max", &entry->mq_msg_max);
	if (ret < 0)
		goto err;
	ret = write_ipc_sysctl("/proc/sys/fs/mqueue/msgsize_max", &entry->mq_msgsize_max);
	if (ret < 0)
		goto err;

	return 0;
err:
	pr_err("Failed to restore ipc namespace tunables\n");
	return ret;
}

static int prepare_ipc_data(int fd)
{
	int ret;
	struct ipc_ns_data ipc;

	ret = read_img(fd, &ipc);
	if (ret <= 0)
		return -EFAULT;
	ret = prepare_ipc_tun(&ipc.entry);
	if (ret < 0)
		return ret;
	return 0;
}

int prepare_ipc_ns(int pid)
{
	int fd, ret;

	fd = open_image_ro(CR_FD_IPCNS, pid);
	if (fd < 0)
		return -1;

	ret = prepare_ipc_data(fd);

	close(fd);
	return ret;
}

