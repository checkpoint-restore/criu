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

#include "protobuf.h"
#include "protobuf/ipc-var.pb-c.h"
#include "protobuf/ipc-shm.pb-c.h"
#include "protobuf/ipc-sem.pb-c.h"
#include "protobuf/ipc-msg.pb-c.h"

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

#ifndef MSG_COPY
#define MSG_COPY		040000
#endif

#ifndef MSG_SET
#define MSG_SET			13
#endif

#ifndef MSG_SET_COPY
#define MSG_SET_COPY		14
#endif

#ifndef SEM_SET
#define SEM_SET			20
#endif

static void pr_ipc_desc_entry(unsigned int loglevel, const IpcDescEntry *desc)
{
	print_on_level(loglevel, "id: %-10d key: 0x%08x ", desc->id, desc->key);
	print_on_level(loglevel, "uid: %-10d gid: %-10d ", desc->uid, desc->gid);
	print_on_level(loglevel, "cuid: %-10d cgid: %-10d ", desc->cuid, desc->cgid);
	print_on_level(loglevel, "mode: %-10o ", desc->mode);
}

static void fill_ipc_desc(int id, IpcDescEntry *desc, const struct ipc_perm *ipcp)
{
	desc->id = id;
	desc->key = ipcp->KEY;
	desc->uid = ipcp->uid;
	desc->gid = ipcp->gid;
	desc->cuid = ipcp->cuid;
	desc->cgid = ipcp->cgid;
	desc->mode = ipcp->mode;
}

static void pr_ipc_sem_array(unsigned int loglevel, int nr, u16 *values)
{
	while (nr--)
		print_on_level(loglevel, "  %-5d", values[nr]);
	print_on_level(loglevel, "\n");
}

#define pr_info_ipc_sem_array(nr, values)	pr_ipc_sem_array(LOG_INFO, nr, values)
#define pr_msg_ipc_sem_array(nr, values)	pr_ipc_sem_array(LOG_MSG, nr, values)

static void pr_info_ipc_sem_entry(const IpcSemEntry *sem)
{
	pr_ipc_desc_entry(LOG_INFO, sem->desc);
	print_on_level(LOG_INFO, "nsems: %-10d\n", sem->nsems);
}

static int dump_ipc_sem_set(int fd, const IpcSemEntry *entry)
{
	int ret, size;
	u16 *values;

	size = sizeof(u16) * entry->nsems;
	values = xmalloc(size);
	if (values == NULL) {
		pr_err("Failed to allocate memory for semaphore set values\n");
		ret = -ENOMEM;
		goto out;
	}
	ret = semctl(entry->desc->id, 0, GETALL, values);
	if (ret < 0) {
		pr_perror("Failed to get semaphore set values");
		ret = -errno;
		goto out;
	}
	pr_info_ipc_sem_array(entry->nsems, values);

	ret = write_img_buf(fd, values, round_up(size, sizeof(u64)));
	if (ret < 0) {
		pr_err("Failed to write IPC message data\n");
		goto out;
	}
out:
	xfree(values);
	return ret;
}

static int dump_ipc_sem_desc(int fd, int id, const struct semid_ds *ds)
{
	IpcSemEntry sem = IPC_SEM_ENTRY__INIT;
	IpcDescEntry desc = IPC_DESC_ENTRY__INIT;
	int ret;

	sem.desc = &desc;
	sem.nsems = ds->sem_nsems;

	fill_ipc_desc(id, sem.desc, &ds->sem_perm);
	pr_info_ipc_sem_entry(&sem);

	ret = pb_write_one(fd, &sem, PB_IPCNS_SEM);
	if (ret < 0) {
		pr_err("Failed to write IPC semaphores set\n");
		return ret;
	}
	return dump_ipc_sem_set(fd, &sem);
}

static int dump_ipc_sem(int fd)
{
	int i, maxid;
	struct seminfo info;
	int slot;

	maxid = semctl(0, 0, SEM_INFO, &info);
	if (maxid < 0) {
		pr_perror("semctl failed");
		return -errno;
	}

	pr_info("IPC semaphore sets: %d\n", info.semusz);
	for (i = 0, slot = 0; i <= maxid; i++) {
		struct semid_ds ds;
		int id, ret;

		id = semctl(i, 0, SEM_STAT, &ds);
		if (id < 0) {
			if (errno == EINVAL)
				continue;
			pr_perror("Failed to get stats for IPC semaphore set");
			break;
		}
		ret = dump_ipc_sem_desc(fd, id, &ds);
		if (!ret)
			slot++;
	}
	if (slot != info.semusz) {
		pr_err("Failed to collect %d (only %d succeeded)\n", info.semusz, slot);
		return -EFAULT;
	}
	return info.semusz;
}

static void pr_info_ipc_msg(int nr, const IpcMsg *msg)
{
	print_on_level(LOG_INFO, "  %-5d: type: %-20ld size: %-10d\n",
		       nr++, msg->mtype, msg->msize);
}

static void pr_info_ipc_msg_entry(const IpcMsgEntry *msg)
{
	pr_ipc_desc_entry(LOG_INFO, msg->desc);
	print_on_level(LOG_INFO, "qbytes: %-10d qnum: %-10d\n",
		       msg->qbytes, msg->qnum);
}

static int dump_ipc_msg_queue_messages(int fd, const IpcMsgEntry *entry,
				       unsigned int msg_nr)
{
	struct msgbuf *message = NULL;
	unsigned int msgmax;
	int ret, msg_cnt = 0;
	struct sysctl_req req[] = {
		{ "kernel/msgmax", &msgmax, CTL_U32 },
		{ },
	};

	ret = sysctl_op(req, CTL_READ);
	if (ret < 0) {
		pr_err("Failed to read max IPC message size\n");
		goto err;
	}

	msgmax += sizeof(struct msgbuf);
	message = xmalloc(msgmax);
	if (message == NULL) {
		pr_err("Failed to allocate memory for IPC message\n");
		return -ENOMEM;
	}

	for (msg_cnt = 0; msg_cnt < msg_nr; msg_cnt++) {
		IpcMsg msg = IPC_MSG__INIT;

		ret = msgrcv(entry->desc->id, message, msgmax, msg_cnt, IPC_NOWAIT | MSG_COPY);
		if (ret < 0) {
			pr_perror("Failed to copy IPC message");
			goto err;
		}

		msg.msize = ret;
		msg.mtype = message->mtype;

		pr_info_ipc_msg(msg_cnt, &msg);

		ret = pb_write_one(fd, &msg, PB_IPCNS_MSG);
		if (ret < 0) {
			pr_err("Failed to write IPC message header\n");
			break;
		}
		ret = write_img_buf(fd, message->mtext, round_up(msg.msize, sizeof(u64)));
		if (ret < 0) {
			pr_err("Failed to write IPC message data\n");
			break;
		}
	}
	ret = 0;
err:
	xfree(message);
	return ret;
}

static int dump_ipc_msg_queue(int fd, int id, const struct msqid_ds *ds)
{
	IpcMsgEntry msg = IPC_MSG_ENTRY__INIT;
	IpcDescEntry desc = IPC_DESC_ENTRY__INIT;
	int ret;

	msg.desc = &desc;
	fill_ipc_desc(id, msg.desc, &ds->msg_perm);
	msg.qbytes = ds->msg_qbytes;
	msg.qnum = ds->msg_qnum;

	pr_info_ipc_msg_entry(&msg);

	ret = pb_write_one(fd, &msg, PB_IPCNS_MSG_ENT);
	if (ret < 0) {
		pr_err("Failed to write IPC message queue\n");
		return ret;
	}
	return dump_ipc_msg_queue_messages(fd, &msg, ds->msg_qnum);
}

static int dump_ipc_msg(int fd)
{
	int i, maxid;
	struct msginfo info;
	int slot;

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
		pr_err("Failed to collect %d message queues (only %d succeeded)\n", info.msgpool, slot);
		return -EFAULT;
	}
	return info.msgpool;
}

static void pr_info_ipc_shm(const IpcShmEntry *shm)
{
	pr_ipc_desc_entry(LOG_INFO, shm->desc);
	print_on_level(LOG_INFO, "size: %-10lu\n", shm->size);
}

static int ipc_sysctl_req(IpcVarEntry *e, int op)
{
	struct sysctl_req req[] = {
		{ "kernel/sem",			e->sem_ctls,		CTL_U32A(e->n_sem_ctls) },
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

/*
 * TODO: Function below should be later improved to locate and dump only dirty
 * pages via updated sys_mincore().
 */
static int dump_ipc_shm_pages(int fd, const IpcShmEntry *shm)
{
	void *data;
	int ret;

	data = shmat(shm->desc->id, NULL, SHM_RDONLY);
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
	IpcShmEntry shm = IPC_SHM_ENTRY__INIT;
	IpcDescEntry desc = IPC_DESC_ENTRY__INIT;
	int ret;

	shm.desc = &desc;
	shm.size = ds->shm_segsz;
	fill_ipc_desc(id, shm.desc, &ds->shm_perm);
	pr_info_ipc_shm(&shm);

	ret = pb_write_one(fd, &shm, PB_IPCNS_SHM);
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
	IpcVarEntry var = IPC_VAR_ENTRY__INIT;
	int ret = -1;

	var.n_sem_ctls	= 4;
	var.sem_ctls	= xmalloc(pb_repeated_size(&var, sem_ctls));
	if (!var.sem_ctls)
		goto err;

	ret = ipc_sysctl_req(&var, CTL_READ);
	if (ret < 0) {
		pr_err("Failed to read IPC variables\n");
		goto err;
	}

	ret = pb_write_one(fd, &var, PB_IPCNS_VAR);
	if (ret < 0) {
		pr_err("Failed to write IPC variables\n");
		goto err;
	}

err:
	xfree(var.sem_ctls);
	return ret;
}

static int dump_ipc_data(const struct cr_fdset *fdset)
{
	int ret;

	ret = dump_ipc_var(fdset_fd(fdset, CR_FD_IPCNS_VAR));
	if (ret < 0)
		return ret;
	ret = dump_ipc_shm(fdset_fd(fdset, CR_FD_IPCNS_SHM));
	if (ret < 0)
		return ret;
	ret = dump_ipc_msg(fdset_fd(fdset, CR_FD_IPCNS_MSG));
	if (ret < 0)
		return ret;
	ret = dump_ipc_sem(fdset_fd(fdset, CR_FD_IPCNS_SEM));
	if (ret < 0)
		return ret;
	return 0;
}

int dump_ipc_ns(int ns_pid, const struct cr_fdset *fdset)
{
	int ret;

	ret = switch_ns(ns_pid, CLONE_NEWIPC, "ipc", NULL);
	if (ret < 0)
		return ret;

	ret = dump_ipc_data(fdset);
	if (ret < 0) {
		pr_err("Failed to write IPC namespace data\n");
		return ret;
	}
	return 0;
}

static void ipc_sem_handler(int fd, void *obj, int show_pages_content)
{
	IpcSemEntry *e = obj;
	u16 *values;
	int size;

	pr_msg("\n");
	size = sizeof(u16) * e->nsems;
	values = xmalloc(size);
	if (values == NULL)
		return;
	if (read_img_buf(fd, values, round_up(size, sizeof(u64))) <= 0)
		return;
	pr_msg_ipc_sem_array(e->nsems, values);
}

void show_ipc_sem(int fd, struct cr_options *o)
{
	pb_show_plain_payload(fd, PB_IPCNS_SEM, ipc_sem_handler, 0);
}

static void ipc_msg_data_handler(int fd, void *obj, int show_pages_content)
{
	IpcMsg *e = obj;

	if (show_pages_content) {
		pr_msg("\n");
		print_image_data(fd, round_up(e->msize, sizeof(u64)));
	} else
		lseek(fd, round_up(e->msize, sizeof(u64)), SEEK_CUR);
}

static void ipc_msg_handler(int fd, void *obj, int show_pages_content)
{
	IpcMsgEntry *e = obj;
	int msg_nr = 0;

	pr_msg("\n");
	while (msg_nr++ < e->qnum)
		pb_show_plain_payload(fd, PB_IPCNS_MSG, ipc_msg_data_handler,
					show_pages_content);

}

void show_ipc_msg(int fd, struct cr_options *o)
{
	pb_show_plain_payload(fd, PB_IPCNS_MSG_ENT, ipc_msg_handler, o->show_pages_content);
}

static void ipc_shm_handler(int fd, void *obj, int show_pages_content)
{
	IpcShmEntry *e = obj;

	if (show_pages_content) {
		pr_msg("\n");
		print_image_data(fd, round_up(e->size, sizeof(u64)));
	} else
		lseek(fd, round_up(e->size, sizeof(u32)), SEEK_CUR);
}

void show_ipc_shm(int fd, struct cr_options *o)
{
	pb_show_plain_payload(fd, PB_IPCNS_SHM, ipc_shm_handler,
				o->show_pages_content);
}

void show_ipc_var(int fd, struct cr_options *o)
{
	pb_show_vertical(fd, PB_IPCNS_VAR);
}

static int prepare_ipc_sem_values(int fd, const IpcSemEntry *entry)
{
	int ret, size;
	u16 *values;

	size = sizeof(u16) * entry->nsems;
	values = xmalloc(size);
	if (values == NULL) {
		pr_err("Failed to allocate memory for semaphores set values\n");
		ret = -ENOMEM;
		goto out;
	}

	ret = read_img_buf(fd, values, round_up(size, sizeof(u64)));
	if (ret < 0) {
		pr_err("Failed to allocate memory for semaphores set values\n");
		ret = -ENOMEM;
		goto out;
	}

	pr_info_ipc_sem_array(entry->nsems, values);

	ret = semctl(entry->desc->id, 0, SETALL, values);
	if (ret < 0) {
		pr_perror("Failed to set semaphores set values");
		ret = -errno;
	}
out:
	xfree(values);
	return ret;
}

static int prepare_ipc_sem_desc(int fd, const IpcSemEntry *entry)
{
	int ret, id;
	struct semid_ds ds;

	id = semget(entry->desc->id, entry->nsems,
		     entry->desc->mode | IPC_CREAT | IPC_EXCL | IPC_PRESET);
	if (id == -1) {
		pr_perror("Failed to create sem set");
		return -errno;
	}

	if (id != entry->desc->id) {
		pr_err("Failed to preset id (%d instead of %d)\n",
							id, entry->desc->id);
		return -EFAULT;
	}

	ret = semctl(id, 0, SEM_STAT, &ds);
	if (ret < 0) {
		pr_perror("Failed to stat sem set");
		return -errno;
	}

	ds.sem_perm.KEY = entry->desc->key;
	ret = semctl(id, 0, SEM_SET, &ds);
	if (ret < 0) {
		pr_perror("Failed to update sem key");
		return -errno;
	}
	ret = prepare_ipc_sem_values(fd, entry);
	if (ret < 0) {
		pr_err("Failed to update sem pages\n");
		return ret;
	}
	return 0;
}

static int prepare_ipc_sem(int pid)
{
	int fd;

	pr_info("Restoring IPC semaphores sets\n");
	fd = open_image_ro(CR_FD_IPCNS_SEM, pid);
	if (fd < 0)
		return -1;

	while (1) {
		int ret;
		IpcSemEntry *entry;

		ret = pb_read_one_eof(fd, &entry, PB_IPCNS_SEM);
		if (ret < 0)
			return -EIO;
		if (ret == 0)
			break;

		pr_info_ipc_sem_entry(entry);

		ret = prepare_ipc_sem_desc(fd, entry);
		ipc_sem_entry__free_unpacked(entry, NULL);

		if (ret < 0) {
			pr_err("Failed to prepare semaphores set\n");
			return ret;
		}
	}
	return close_safe(&fd);
}

static int prepare_ipc_msg_queue_messages(int fd, const IpcMsgEntry *entry)
{
	IpcMsg *msg = NULL;
	int msg_nr = 0;
	int ret = 0;

	while (msg_nr < entry->qnum) {
		struct msgbuf {
			long mtype;
			char mtext[MSGMAX];
		} data;

		ret = pb_read_one(fd, &msg, PB_IPCNS_MSG);
		if (ret <= 0)
			return -EIO;

		pr_info_ipc_msg(msg_nr, msg);

		if (msg->msize > MSGMAX) {
			ret = -1;
			pr_err("Unsupported message size: %d (MAX: %d)\n",
						msg->msize, MSGMAX);
			break;
		}

		ret = read_img_buf(fd, data.mtext, round_up(msg->msize, sizeof(u64)));
		if (ret < 0) {
			pr_err("Failed to read IPC message data\n");
			break;
		}

		data.mtype = msg->mtype;
		ret = msgsnd(entry->desc->id, &data, msg->msize, IPC_NOWAIT);
		if (ret < 0) {
			pr_perror("Failed to send IPC message");
			ret = -errno;
			break;
		}
		msg_nr++;
	}

	if (msg)
		ipc_msg__free_unpacked(msg, NULL);
	return ret;
}

static int prepare_ipc_msg_queue(int fd, const IpcMsgEntry *entry)
{
	int ret, id;
	struct msqid_ds ds;

	id = msgget(entry->desc->id,
		     entry->desc->mode | IPC_CREAT | IPC_EXCL | IPC_PRESET);
	if (id == -1) {
		pr_perror("Failed to create message queue");
		return -errno;
	}

	if (id != entry->desc->id) {
		pr_err("Failed to preset id (%d instead of %d)\n",
							id, entry->desc->id);
		return -EFAULT;
	}

	ret = msgctl(id, MSG_STAT, &ds);
	if (ret < 0) {
		pr_perror("Failed to stat message queue");
		return -errno;
	}

	ds.msg_perm.KEY = entry->desc->key;
	ds.msg_qbytes = entry->qbytes;
	ret = msgctl(id, MSG_SET, &ds);
	if (ret < 0) {
		pr_perror("Failed to update message key");
		return -errno;
	}
	ret = prepare_ipc_msg_queue_messages(fd, entry);
	if (ret < 0) {
		pr_err("Failed to update message queue messages\n");
		return ret;
	}
	return 0;
}

static int prepare_ipc_msg(int pid)
{
	int fd;

	pr_info("Restoring IPC message queues\n");
	fd = open_image_ro(CR_FD_IPCNS_MSG, pid);
	if (fd < 0)
		return -1;

	while (1) {
		int ret;
		IpcMsgEntry *entry;

		ret = pb_read_one_eof(fd, &entry, PB_IPCNS_MSG_ENT);
		if (ret < 0) {
			pr_err("Failed to read IPC messages queue\n");
			return -EIO;
		}
		if (ret == 0)
			break;

		pr_info_ipc_msg_entry(entry);

		ret = prepare_ipc_msg_queue(fd, entry);
		ipc_msg_entry__free_unpacked(entry, NULL);

		if (ret < 0) {
			pr_err("Failed to prepare messages queue\n");
			return ret;
		}
	}
	return close_safe(&fd);
}

static int prepare_ipc_shm_pages(int fd, const IpcShmEntry *shm)
{
	int ret;
	void *data;

	data = shmat(shm->desc->id, NULL, 0);
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

static int prepare_ipc_shm_seg(int fd, const IpcShmEntry *shm)
{
	int ret, id;
	struct shmid_ds ds;

	id = shmget(shm->desc->id, shm->size,
		     shm->desc->mode | IPC_CREAT | IPC_EXCL | IPC_PRESET);
	if (id == -1) {
		pr_perror("Failed to create shm segment");
		return -errno;
	}

	if (id != shm->desc->id) {
		pr_err("Failed to preset id (%d instead of %d)\n",
							id, shm->desc->id);
		return -EFAULT;
	}

	ret = shmctl(id, SHM_STAT, &ds);
	if (ret < 0) {
		pr_perror("Failed to stat shm segment");
		return -errno;
	}

	ds.shm_perm.KEY = shm->desc->key;
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
		int ret;
		IpcShmEntry *shm;

		ret = pb_read_one_eof(fd, &shm, PB_IPCNS_SHM);
		if (ret < 0) {
			pr_err("Failed to read IPC shared memory segment\n");
			return -EIO;
		}
		if (ret == 0)
			break;

		pr_info_ipc_shm(shm);

		ret = prepare_ipc_shm_seg(fd, shm);
		ipc_shm_entry__free_unpacked(shm, NULL);

		if (ret < 0) {
			pr_err("Failed to prepare shm segment\n");
			return ret;
		}
	}
	return close_safe(&fd);
}

static int prepare_ipc_var(int pid)
{
	int fd, ret;
	IpcVarEntry *var;

	pr_info("Restoring IPC variables\n");
	fd = open_image_ro(CR_FD_IPCNS_VAR, pid);
	if (fd < 0)
		return -1;

	ret = pb_read_one(fd, &var, PB_IPCNS_VAR);
	if (ret <= 0) {
		pr_err("Failed to read IPC namespace variables\n");
		return -EFAULT;
	}

	ipc_sysctl_req(var, CTL_PRINT);

	ret = ipc_sysctl_req(var, CTL_WRITE);
	ipc_var_entry__free_unpacked(var, NULL);

	if (ret < 0) {
		pr_err("Failed to prepare IPC namespace variables\n");
		return -EFAULT;
	}
	return close_safe(&fd);
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
	ret = prepare_ipc_msg(pid);
	if (ret < 0)
		return ret;
	ret = prepare_ipc_sem(pid);
	if (ret < 0)
		return ret;
	return 0;
}
