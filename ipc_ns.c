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

#if defined (__GLIBC__) && __GLIBC__ >= 2
#define KEY __key
#else
#define KEY key
#endif

#ifndef IPC_PRESET
#define IPC_PRESET		00040000
#endif

#ifndef SHM_SET
#define SHM_SET			15
#endif

#ifndef MSGMAX
#define MSGMAX			8192
#endif

#ifndef MSG_STEAL

#define MSG_STEAL		040000

/* message buffer for msgrcv in case of array calls */
struct msgbuf_a {
	long mtype;         /* type of message */
	size_t msize;       /* size of message */
	char mtext[0];      /* message text */
};

#endif

static void print_ipc_desc_entry(const struct ipc_desc_entry *desc)
{
	pr_info("id: %-10d key: 0x%08x ", desc->id, desc->key);
	pr_info("uid: %-10d gid: %-10d ", desc->uid, desc->gid);
	pr_info("cuid: %-10d cgid: %-10d ", desc->cuid, desc->cgid);
	pr_info("mode: %-10o ", desc->mode);
}

static void fill_ipc_desc(int id, struct ipc_desc_entry *desc,
				const struct ipc_perm *ipcp)
{
	desc->id = id;
	desc->key = ipcp->KEY;
	desc->uid = ipcp->uid;
	desc->gid = ipcp->gid;
	desc->cuid = ipcp->cuid;
	desc->cgid = ipcp->cgid;
	desc->mode = ipcp->mode;
}

static void print_ipc_msg(int nr, const struct ipc_msg *msg)
{
	pr_info("  %-5d: type: %-20ld size: %-10d\n",
		nr++, msg->mtype, msg->msize);
}

static void print_ipc_msg_entry(const struct ipc_msg_entry *msg)
{
	print_ipc_desc_entry(&msg->desc);
	pr_info ("qbytes: %-10d qnum: %-10d\n", msg->qbytes, msg->qnum);
}

static int dump_ipc_msg_queue_messages(int fd, const struct ipc_msg_entry *entry, size_t cbytes)
{
	void *msg_array, *ptr;
	size_t array_size;
	int ret, msg_nr = 0;

	array_size = entry->qnum * sizeof(struct msgbuf_a) + cbytes;
	msg_array = ptr = xmalloc(array_size);
	if (msg_array == NULL) {
		pr_err("Failed to allocate memory for IPC messages\n");
		return -ENOMEM;
	}

	ret = msgrcv(entry->desc.id, msg_array, array_size, 0, IPC_NOWAIT | MSG_STEAL);
	if (ret < 0) {
		pr_perror("Failed to receive IPC messages array");
		goto err;
	}

	while (msg_nr < entry->qnum) {
		struct msgbuf_a *data = ptr;
		struct ipc_msg msg;

		msg.msize = data->msize;
		msg.mtype = data->mtype;

		print_ipc_msg(msg_nr, &msg);

		ret = write_img(fd, &msg);
		if (ret < 0) {
			pr_err("Failed to write IPC message header\n");
			break;
		}
		ret = write_img_buf(fd, data->mtext, round_up(msg.msize, sizeof(u64)));
		if (ret < 0) {
			pr_err("Failed to write IPC message data\n");
			break;
		}
		msg_nr++;
		ptr += sizeof(struct msgbuf_a) + data->msize;
	}
	ret = 0;
err:
	xfree(msg_array);
	return ret;
}

static int dump_ipc_msg_queue(int fd, int id, const struct msqid_ds *ds)
{
	struct ipc_msg_entry msg;
	int ret;

	fill_ipc_desc(id, &msg.desc, &ds->msg_perm);
	msg.qbytes = ds->msg_qbytes;
	msg.qnum = ds->msg_qnum;
	print_ipc_msg_entry(&msg);

	ret = write_img(fd, &msg);
	if (ret < 0) {
		pr_err("Failed to write IPC message queue\n");
		return ret;
	}
	return dump_ipc_msg_queue_messages(fd, &msg, ds->msg_cbytes);
}

static int dump_ipc_msg(int fd)
{
	int i, maxid;
	struct msginfo info;
	int err, slot;

	maxid = msgctl(0, MSG_INFO, (struct msqid_ds *)&info);
	if (maxid < 0) {
		pr_perror("msgctl failed");
		return -errno;
	}

	pr_info("IPC message queues: %d\n", info.msgpool);
	for (i = 0, slot = 0; i <= maxid; i++) {
		struct msqid_ds ds;
		int id, ret;

		id = msgctl(i, MSG_STAT, &ds);
		if (id < 0) {
			if (errno == EINVAL)
				continue;
			pr_perror("Failed to get stats for IPC message queue");
			break;
		}
		ret = dump_ipc_msg_queue(fd, id, &ds);
		if (!ret)
			slot++;
	}
	if (slot != info.msgpool) {
		pr_err("Failed to collect %d (only %d succeeded)\n", info.msgpool, slot);
		return -EFAULT;
	}
	return info.msgpool;
}

static void print_ipc_shm(const struct ipc_shm_entry *shm)
{
	print_ipc_desc_entry(&shm->desc);
	pr_info("size: %-10lu\n", shm->size);
}

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

/*
 * TODO: Function below should be later improved to locate and dump only dirty
 * pages via updated sys_mincore().
 */
static int dump_ipc_shm_pages(int fd, const struct ipc_shm_entry *shm)
{
	void *data;
	int ret;

	data = shmat(shm->desc.id, NULL, SHM_RDONLY);
	if (data == (void *)-1) {
		pr_perror("Failed to attach IPC shared memory");
		return -errno;
	}
	ret = write_img_buf(fd, data, round_up(shm->size, sizeof(u32)));
	if (ret < 0) {
		pr_err("Failed to write IPC shared memory data\n");
		return ret;
	}
	if (shmdt(data)) {
		pr_perror("Failed to detach IPC shared memory");
		return -errno;
	}
	return 0;
}

static int dump_ipc_shm_seg(int fd, int id, const struct shmid_ds *ds)
{
	struct ipc_shm_entry shm;
	int ret;

	fill_ipc_desc(id, &shm.desc, &ds->shm_perm);
	shm.size = ds->shm_segsz;
	print_ipc_shm(&shm);

	ret = write_img(fd, &shm);
	if (ret < 0) {
		pr_err("Failed to write IPC shared memory segment\n");
		return ret;
	}
	return dump_ipc_shm_pages(fd, &shm);
}

static int dump_ipc_shm(int fd)
{
	int i, maxid, slot;
	struct shm_info info;

	maxid = shmctl(0, SHM_INFO, (void *)&info);
	if (maxid < 0) {
		pr_perror("shmctl(SHM_INFO) failed");
		return -errno;
	}

	pr_info("IPC shared memory segments: %d\n", info.used_ids);
	for (i = 0, slot = 0; i <= maxid; i++) {
		struct shmid_ds ds;
		int id, ret;

		id = shmctl(i, SHM_STAT, &ds);
		if (id < 0) {
			if (errno == EINVAL)
				continue;
			pr_perror("Failed to get stats for IPC shared memory");
			break;
		}

		if (ds.shm_nattch != 0) {
			pr_err("Migration of attached IPC shared memory "
			       "segments is not supported yet\n");
			return -EFAULT;
		}

		ret = dump_ipc_shm_seg(fd, id, &ds);
		if (ret < 0)
			return ret;
		slot++;
	}
	if (slot != info.used_ids) {
		pr_err("Failed to collect %d (only %d succeeded)\n",
				info.used_ids, slot);
		return -EFAULT;
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

static int dump_ipc_data(const struct cr_fdset *fdset)
{
	int ret;

	ret = dump_ipc_var(fdset->fds[CR_FD_IPCNS_VAR]);
	if (ret < 0)
		return ret;
	ret = dump_ipc_shm(fdset->fds[CR_FD_IPCNS_SHM]);
	if (ret < 0)
		return ret;
	ret = dump_ipc_msg(fdset->fds[CR_FD_IPCNS_MSG]);
	if (ret < 0)
		return ret;
	ret = dump_ipc_sem(0);
	if (ret < 0)
		return ret;
	return 0;
}

int dump_ipc_ns(int ns_pid, const struct cr_fdset *fdset)
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

static void show_ipc_shm_entries(int fd)
{
	pr_info("\nShared memory segments:\n");
	while (1) {
		int ret;
		struct ipc_shm_entry shm;

		ret = read_img_eof(fd, &shm);
		if (ret <= 0)
			return;

		print_ipc_shm(&shm);

		if (lseek(fd, round_up(shm.size, sizeof(u32)), SEEK_CUR) == (off_t) -1)
			return;
	}
}

void show_ipc_shm(int fd)
{
	pr_img_head(CR_FD_IPCNS);
	show_ipc_shm_entries(fd);
	pr_img_tail(CR_FD_IPCNS);
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

static int prepare_ipc_shm_pages(int fd, const struct ipc_shm_entry *shm)
{
	int ret;
	void *data;

	data = shmat(shm->desc.id, NULL, 0);
	if (data == (void *)-1) {
		pr_perror("Failed to attach IPC shared memory");
		return -errno;
	}
	ret = read_img_buf(fd, data, round_up(shm->size, sizeof(u32)));
	if (ret < 0) {
		pr_err("Failed to read IPC shared memory data\n");
		return ret;
	}
	if (shmdt(data)) {
		pr_perror("Failed to detach IPC shared memory");
		return -errno;
	}
	return 0;
}

static int prepare_ipc_shm_seg(int fd, const struct ipc_shm_entry *shm)
{
	int ret, id;
	struct shmid_ds ds;

	id = shmget(shm->desc.id, shm->size,
		     shm->desc.mode | IPC_CREAT | IPC_EXCL | IPC_PRESET);
	if (id == -1) {
		pr_perror("Failed to create shm segment");
		return -errno;
	}

	if (id != shm->desc.id) {
		pr_err("Failed to preset id (%d instead of %d)\n",
							id, shm->desc.id);
		return -EFAULT;
	}

	ret = shmctl(id, SHM_STAT, &ds);
	if (ret < 0) {
		pr_perror("Failed to stat shm segment");
		return -errno;
	}

	ds.shm_perm.KEY = shm->desc.key;
	ret = shmctl(id, SHM_SET, &ds);
	if (ret < 0) {
		pr_perror("Failed to update shm key");
		return -errno;
	}
	ret = prepare_ipc_shm_pages(fd, shm);
	if (ret < 0) {
		pr_err("Failed to update shm pages\n");
		return ret;
	}
	return 0;
}

static int prepare_ipc_shm(int pid)
{
	int fd;

	pr_info("Restoring IPC shared memory\n");
	fd = open_image_ro(CR_FD_IPCNS_SHM, pid);
	if (fd < 0)
		return -1;

	while (1) {
		int ret, id;
		struct ipc_shm_entry shm;

		ret = read_img_eof(fd, &shm);
		if (ret < 0) {
			pr_err("Failed to read IPC shared memory segment\n");
			return -EIO;
		}
		if (ret == 0)
			break;

		print_ipc_shm(&shm);

		ret = prepare_ipc_shm_seg(fd, &shm);
		if (ret < 0) {
			pr_err("Failed to prepare shm segment\n");
			return ret;
		}
	}
	return 0;
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
	if (ret <= 0) {
		pr_err("Failed to read IPC namespace variables\n");
		return -EFAULT;
	}

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
	ret = prepare_ipc_shm(pid);
	if (ret < 0)
		return ret;
	return 0;
}
