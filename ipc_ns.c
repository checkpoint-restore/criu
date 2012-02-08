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
#include "sysctl.h"

static int ipc_sysctl_req(struct ipc_var_entry *e, int op)
{
	struct sysctl_req req[] = {
		{ "kernel/sem",			e->sem_ctls,		CTL_U32A(4) },
		{ "kernel/msgmax",		&e->msg_ctlmax,		CTL_U32 },
		{ "kernel/msgmnb",		&e->msg_ctlmnb,		CTL_U32 },
		{ "kernel/msgmni",		&e->msg_ctlmni,		CTL_U32 },
		{ "kernel/auto_msgmni",		&e->auto_msgmni,	CTL_U32 },
		{ "kernel/shmmax",		&e->shm_ctlmax,		CTL_U64 },
		{ "kernel/shmall",		&e->shm_ctlall,		CTL_U64 },
		{ "kernel/shmmni",		&e->shm_ctlmni,		CTL_U32 },
		{ "kernel/shm_rmid_forced",	&e->shm_rmid_forced,	CTL_U32 },
		{ "fs/mqueue/queues_max",	&e->mq_queues_max,	CTL_U32 },
		{ "fs/mqueue/msg_max",		&e->mq_msg_max,		CTL_U32 },
		{ "fs/mqueue/msgsize_max",	&e->mq_msgsize_max,	CTL_U32 },
		{ },
	};

	return sysctl_op(req, op);
}

static int dump_ipc_msg(void *data)
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

static int dump_ipc_sem(void *data)
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

static int dump_ipc_shm(void *data)
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

static int dump_ipc_var(int fd)
{
	int ret;
	struct ipc_var_entry var;

	ret = ipc_sysctl_req(&var, CTL_READ);
	if (ret < 0) {
		pr_err("Failed to read IPC variables\n");
		return ret;
	}

	ret = write_img(fd, &var);
	if (ret < 0) {
		pr_err("Failed to write IPC variables\n");
		return ret;
	}
	return 0;
}

static int dump_ipc_data(struct cr_fdset *fdset)
{
	int ret;

	ret = dump_ipc_var(fdset->fds[CR_FD_IPCNS_VAR]);
	if (ret < 0)
		return ret;
	ret = dump_ipc_shm(0);
	if (ret < 0)
		return ret;
	ret = dump_ipc_msg(0);
	if (ret < 0)
		return ret;
	ret = dump_ipc_sem(0);
	if (ret < 0)
		return ret;
	return 0;
}

int dump_ipc_ns(int ns_pid, struct cr_fdset *fdset)
{
	int fd, ret;

	ret = switch_ns(ns_pid, CLONE_NEWIPC, "ipc");
	if (ret < 0)
		return ret;

	ret = dump_ipc_data(fdset);
	if (ret < 0) {
		pr_err("Failed to write IPC namespace data\n");
		return ret;
	}
	return 0;
}

static void show_var_entry(struct ipc_var_entry *entry)
{
	ipc_sysctl_req(entry, CTL_PRINT);
}

static void show_ipc_var_entry(int fd)
{
	int ret;
	struct ipc_var_entry var;

	ret = read_img_eof(fd, &var);
	if (ret <= 0)
		return;
	show_var_entry(&var);
}

void show_ipc_var(int fd)
{
	pr_img_head(CR_FD_IPCNS);
	show_ipc_var_entry(fd);
	pr_img_tail(CR_FD_IPCNS);
}

static int prepare_ipc_var(int pid)
{
	int fd, ret;
	struct ipc_var_entry var;

	pr_info("Restoring IPC variables\n");
	fd = open_image_ro(CR_FD_IPCNS_VAR, pid);
	if (fd < 0)
		return -1;

	ret = read_img(fd, &var);
	if (ret <= 0)
		return -EFAULT;

	show_var_entry(&var);

	return ipc_sysctl_req(&var, CTL_WRITE);
}

int prepare_ipc_ns(int pid)
{
	int ret;

	pr_info("Restoring IPC namespace\n");
	ret = prepare_ipc_var(pid);
	if (ret < 0)
		return ret;
	return 0;
}
