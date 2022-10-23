#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <sys/msg.h>
#include <sys/sem.h>
#include <sys/shm.h>
#include <sched.h>

#include "util.h"
#include "cr_options.h"
#include "imgset.h"
#include "namespaces.h"
#include "sysctl.h"
#include "ipc_ns.h"
#include "shmem.h"
#include "types.h"

#include "protobuf.h"
#include "images/ipc-var.pb-c.h"
#include "images/ipc-shm.pb-c.h"
#include "images/ipc-sem.pb-c.h"
#include "images/ipc-msg.pb-c.h"

#if defined(__GLIBC__) && __GLIBC__ >= 2
#define KEY __key
#else
#define KEY key
#endif

#ifndef MSGMAX
#define MSGMAX 8192
#endif

#ifndef MSG_COPY
#define MSG_COPY 040000
#endif

static void pr_ipc_desc_entry(const IpcDescEntry *desc)
{
	pr_info("id: %-10d key: %#08x uid: %-10d gid: %-10d "
		"cuid: %-10d cgid: %-10d mode: %-10o ",
		desc->id, desc->key, desc->uid, desc->gid, desc->cuid, desc->cgid, desc->mode);
}

static void fill_ipc_desc(int id, IpcDescEntry *desc, const struct ipc_perm *ipcp)
{
	desc->id = id;
	desc->key = ipcp->KEY;
	desc->uid = userns_uid(ipcp->uid);
	desc->gid = userns_gid(ipcp->gid);
	desc->cuid = userns_uid(ipcp->cuid);
	desc->cgid = userns_gid(ipcp->cgid);
	desc->mode = ipcp->mode;
}

static void pr_ipc_sem_array(int nr, u16 *values)
{
	while (nr--)
		pr_info("  %-5d", values[nr]); // no \n
	pr_info("\n");
}

#define pr_info_ipc_sem_array(nr, values) pr_ipc_sem_array(nr, values)

static void pr_info_ipc_sem_entry(const IpcSemEntry *sem)
{
	pr_ipc_desc_entry(sem->desc);
	pr_info("nsems: %-10d\n", sem->nsems);
}

static int dump_ipc_sem_set(struct cr_img *img, const IpcSemEntry *sem)
{
	size_t rounded;
	int ret, size;
	u16 *values;

	size = sizeof(u16) * sem->nsems;
	rounded = round_up(size, sizeof(u64));
	values = xmalloc(rounded);
	if (values == NULL) {
		pr_err("Failed to allocate memory for semaphore set values\n");
		ret = -ENOMEM;
		goto out;
	}
	ret = semctl(sem->desc->id, 0, GETALL, values);
	if (ret < 0) {
		pr_perror("Failed to get semaphore set values");
		ret = -errno;
		goto out;
	}
	pr_info_ipc_sem_array(sem->nsems, values);

	memzero((void *)values + size, rounded - size);
	ret = write_img_buf(img, values, rounded);
	if (ret < 0) {
		pr_err("Failed to write IPC message data\n");
		goto out;
	}
out:
	xfree(values);
	return ret;
}

static int dump_ipc_sem_desc(struct cr_img *img, int id, const struct semid_ds *ds)
{
	IpcSemEntry sem = IPC_SEM_ENTRY__INIT;
	IpcDescEntry desc = IPC_DESC_ENTRY__INIT;
	int ret;

	sem.desc = &desc;
	sem.nsems = ds->sem_nsems;

	fill_ipc_desc(id, sem.desc, &ds->sem_perm);
	pr_info_ipc_sem_entry(&sem);

	ret = pb_write_one(img, &sem, PB_IPC_SEM);
	if (ret < 0) {
		pr_err("Failed to write IPC semaphores set\n");
		return ret;
	}
	return dump_ipc_sem_set(img, &sem);
}

static int dump_ipc_sem(struct cr_img *img)
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
		ret = dump_ipc_sem_desc(img, id, &ds);
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
	pr_info("  %-5d: type: %-20" PRId64 " size: %-10d\n", nr++, msg->mtype, msg->msize);
}

static void pr_info_ipc_msg_entry(const IpcMsgEntry *msg)
{
	pr_ipc_desc_entry(msg->desc);
	pr_info("qbytes: %-10d qnum: %-10d\n", msg->qbytes, msg->qnum);
}

static int dump_ipc_msg_queue_messages(struct cr_img *img, const IpcMsgEntry *msq, unsigned int msg_nr)
{
	struct msgbuf *message = NULL;
	unsigned int msgmax;
	int ret, msg_cnt = 0;
	struct sysctl_req req[] = {
		{ "kernel/msgmax", &msgmax, CTL_U32 },
	};

	ret = sysctl_op(req, ARRAY_SIZE(req), CTL_READ, CLONE_NEWIPC);
	if (ret < 0) {
		pr_err("Failed to read max IPC message size\n");
		goto err;
	}

	msgmax += sizeof(struct msgbuf);
	message = xmalloc(round_up(msgmax, sizeof(u64)));
	if (message == NULL) {
		pr_err("Failed to allocate memory for IPC message\n");
		return -ENOMEM;
	}

	for (msg_cnt = 0; msg_cnt < msg_nr; msg_cnt++) {
		IpcMsg msg = IPC_MSG__INIT;
		size_t rounded;

		ret = msgrcv(msq->desc->id, message, msgmax, msg_cnt, IPC_NOWAIT | MSG_COPY);
		if (ret < 0) {
			pr_perror("Failed to copy IPC message");
			goto err;
		}

		msg.msize = ret;
		msg.mtype = message->mtype;

		pr_info_ipc_msg(msg_cnt, &msg);

		ret = pb_write_one(img, &msg, PB_IPCNS_MSG);
		if (ret < 0) {
			pr_err("Failed to write IPC message header\n");
			break;
		}

		rounded = round_up(msg.msize, sizeof(u64));
		memzero(((void *)message->mtext + msg.msize), rounded - msg.msize);
		ret = write_img_buf(img, message->mtext, rounded);
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

static int dump_ipc_msg_queue(struct cr_img *img, int id, const struct msqid_ds *ds)
{
	IpcMsgEntry msg = IPC_MSG_ENTRY__INIT;
	IpcDescEntry desc = IPC_DESC_ENTRY__INIT;
	int ret;

	msg.desc = &desc;
	fill_ipc_desc(id, msg.desc, &ds->msg_perm);
	msg.qbytes = ds->msg_qbytes;
	msg.qnum = ds->msg_qnum;

	pr_info_ipc_msg_entry(&msg);

	ret = pb_write_one(img, &msg, PB_IPCNS_MSG_ENT);
	if (ret < 0) {
		pr_err("Failed to write IPC message queue\n");
		return ret;
	}
	return dump_ipc_msg_queue_messages(img, &msg, ds->msg_qnum);
}

static int dump_ipc_msg(struct cr_img *img)
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
		ret = dump_ipc_msg_queue(img, id, &ds);
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
	pr_ipc_desc_entry(shm->desc);
	pr_info("size: %-10" PRIu64 "\n", shm->size);
}

#define NR_MANDATORY_IPC_SYSCTLS 9

static int ipc_sysctl_req(IpcVarEntry *e, int op)
{
	int i;

	struct sysctl_req req[] = {
		{ "kernel/sem", e->sem_ctls, CTL_U32A(e->n_sem_ctls) },
		{ "kernel/msgmax", &e->msg_ctlmax, CTL_U32 },
		{ "kernel/msgmnb", &e->msg_ctlmnb, CTL_U32 },
		{ "kernel/auto_msgmni", &e->auto_msgmni, CTL_U32 },
		{ "kernel/msgmni", &e->msg_ctlmni, CTL_U32 },
		{ "kernel/shmmax", &e->shm_ctlmax, CTL_U64 },
		{ "kernel/shmall", &e->shm_ctlall, CTL_U64 },
		{ "kernel/shmmni", &e->shm_ctlmni, CTL_U32 },
		{ "kernel/shm_rmid_forced", &e->shm_rmid_forced, CTL_U32 },
		/* We have 9 mandatory sysctls above and 8 optional below */
		{ "fs/mqueue/queues_max", &e->mq_queues_max, CTL_U32 },
		{ "fs/mqueue/msg_max", &e->mq_msg_max, CTL_U32 },
		{ "fs/mqueue/msgsize_max", &e->mq_msgsize_max, CTL_U32 },
		{ "fs/mqueue/msg_default", &e->mq_msg_default, CTL_U32 },
		{ "fs/mqueue/msgsize_default", &e->mq_msgsize_default, CTL_U32 },
		{ "kernel/msg_next_id", &e->msg_next_id, CTL_U32 },
		{ "kernel/sem_next_id", &e->sem_next_id, CTL_U32 },
		{ "kernel/shm_next_id", &e->shm_next_id, CTL_U32 },
	};

	int nr = NR_MANDATORY_IPC_SYSCTLS;

	/* Skip sysctls which can't be set or haven't existed on dump */
	if (access("/proc/sys/fs/mqueue", X_OK))
		pr_info("Mqueue sysctls are missing\n");
	else {
		nr += 3;
		if (e->has_mq_msg_default) {
			req[nr++] = req[12];
			req[nr++] = req[13];
		}
	}
	if (e->has_msg_next_id)
		req[nr++] = req[14];
	if (e->has_sem_next_id)
		req[nr++] = req[15];
	if (e->has_shm_next_id)
		req[nr++] = req[16];

	for (i = 0; i < nr; i++)
		req[i].flags = CTL_FLAGS_IPC_EACCES_SKIP;

	return sysctl_op(req, nr, op, CLONE_NEWIPC);
}

static int dump_ipc_shm_pages(const IpcShmEntry *shm)
{
	int ret;
	void *data;

	data = shmat(shm->desc->id, NULL, SHM_RDONLY);
	if (data == (void *)-1) {
		pr_perror("Failed to attach IPC shared memory");
		return -errno;
	}

	ret = dump_one_sysv_shmem(data, shm->size, shm->desc->id);

	if (shmdt(data)) {
		pr_perror("Failed to detach IPC shared memory");
		return -errno;
	}
	return ret;
}

static int dump_shm_hugetlb_flag(IpcShmEntry *shm, int id, unsigned long size)
{
	void *addr;
	int ret, hugetlb_flag, exit_code = -1;
	struct stat st;
	char path[64];

	addr = shmat(id, NULL, SHM_RDONLY);
	if (addr == (void *)-1) {
		pr_perror("Failed to attach shm");
		return -1;
	}

	/* The shm segment size may not be aligned,
	 * we need to align it up to next page size
	 */
	size = (size + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
	snprintf(path, sizeof(path), "/proc/self/map_files/%lx-%lx", (unsigned long)addr, (unsigned long)addr + size);

	ret = stat(path, &st);
	if (ret < 0) {
		pr_perror("Can't stat map_files");
		goto detach;
	}

	if (is_hugetlb_dev(st.st_dev, &hugetlb_flag)) {
		shm->has_hugetlb_flag = true;
		shm->hugetlb_flag = hugetlb_flag | SHM_HUGETLB;
	}

	exit_code = 0;
detach:
	shmdt(addr);
	return exit_code;
}

static int dump_ipc_shm_seg(struct cr_img *img, int id, const struct shmid_ds *ds)
{
	IpcShmEntry shm = IPC_SHM_ENTRY__INIT;
	IpcDescEntry desc = IPC_DESC_ENTRY__INIT;
	int ret;

	shm.desc = &desc;
	shm.size = ds->shm_segsz;
	shm.has_in_pagemaps = true;
	shm.in_pagemaps = true;

	if (dump_shm_hugetlb_flag(&shm, id, ds->shm_segsz))
		return -1;

	fill_ipc_desc(id, shm.desc, &ds->shm_perm);
	pr_info_ipc_shm(&shm);

	ret = pb_write_one(img, &shm, PB_IPC_SHM);
	if (ret < 0) {
		pr_err("Failed to write IPC shared memory segment\n");
		return ret;
	}
	return dump_ipc_shm_pages(&shm);
}

static int dump_ipc_shm(struct cr_img *img)
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

		ret = dump_ipc_shm_seg(img, id, &ds);
		if (ret < 0)
			return ret;
		slot++;
	}
	if (slot != info.used_ids) {
		pr_err("Failed to collect %d (only %d succeeded)\n", info.used_ids, slot);
		return -EFAULT;
	}
	return 0;
}

static int dump_ipc_var(struct cr_img *img)
{
	IpcVarEntry var = IPC_VAR_ENTRY__INIT;
	int ret = -1;

	var.n_sem_ctls = 4;
	var.sem_ctls = xmalloc(pb_repeated_size(&var, sem_ctls));
	if (!var.sem_ctls)
		goto err;
	var.has_mq_msg_default = true;
	var.has_mq_msgsize_default = true;
	var.has_msg_next_id = true;
	var.has_sem_next_id = true;
	var.has_shm_next_id = true;

	ret = ipc_sysctl_req(&var, CTL_READ);
	if (ret < 0) {
		pr_err("Failed to read IPC variables\n");
		goto err;
	}

	/*
	 * One can not write to msg_next_xxx sysctls -1,
	 * which is their initial value
	 */
	if (var.msg_next_id == -1)
		var.has_msg_next_id = false;
	if (var.sem_next_id == -1)
		var.has_sem_next_id = false;
	if (var.shm_next_id == -1)
		var.has_shm_next_id = false;

	ret = pb_write_one(img, &var, PB_IPC_VAR);
	if (ret < 0) {
		pr_err("Failed to write IPC variables\n");
		goto err;
	}

err:
	xfree(var.sem_ctls);
	return ret;
}

static int dump_ipc_data(const struct cr_imgset *imgset)
{
	int ret;

	ret = dump_ipc_var(img_from_set(imgset, CR_FD_IPC_VAR));
	if (ret < 0)
		return ret;
	ret = dump_ipc_shm(img_from_set(imgset, CR_FD_IPCNS_SHM));
	if (ret < 0)
		return ret;
	ret = dump_ipc_msg(img_from_set(imgset, CR_FD_IPCNS_MSG));
	if (ret < 0)
		return ret;
	ret = dump_ipc_sem(img_from_set(imgset, CR_FD_IPCNS_SEM));
	if (ret < 0)
		return ret;
	return 0;
}

int dump_ipc_ns(int ns_id)
{
	int ret;
	struct cr_imgset *imgset;

	imgset = cr_imgset_open(ns_id, IPCNS, O_DUMP);
	if (imgset == NULL)
		return -1;

	ret = dump_ipc_data(imgset);
	if (ret < 0) {
		pr_err("Failed to write IPC namespace data\n");
		goto err;
	}

err:
	close_cr_imgset(&imgset);
	return ret < 0 ? -1 : 0;
}

static int prepare_ipc_sem_values(struct cr_img *img, const IpcSemEntry *sem)
{
	int ret, size;
	u16 *values;

	size = round_up(sizeof(u16) * sem->nsems, sizeof(u64));
	values = xmalloc(size);
	if (values == NULL) {
		pr_err("Failed to allocate memory for semaphores set values\n");
		ret = -ENOMEM;
		goto out;
	}

	ret = read_img_buf(img, values, size);
	if (ret < 0) {
		pr_err("Failed to allocate memory for semaphores set values\n");
		ret = -ENOMEM;
		goto out;
	}

	pr_info_ipc_sem_array(sem->nsems, values);

	ret = semctl(sem->desc->id, 0, SETALL, values);
	if (ret < 0) {
		pr_perror("Failed to set semaphores set values");
		ret = -errno;
	}
out:
	xfree(values);
	return ret;
}

static int prepare_ipc_sem_desc(struct cr_img *img, const IpcSemEntry *sem)
{
	int ret, id;
	struct sysctl_req req[] = {
		{ "kernel/sem_next_id", &sem->desc->id, CTL_U32, CTL_FLAGS_IPC_EACCES_SKIP },
	};
	struct semid_ds semid;

	ret = sysctl_op(req, ARRAY_SIZE(req), CTL_WRITE, CLONE_NEWIPC);
	if (ret < 0) {
		pr_err("Failed to set desired IPC sem ID\n");
		return ret;
	}

	id = semget(sem->desc->key, sem->nsems, sem->desc->mode | IPC_CREAT | IPC_EXCL);
	if (id == -1) {
		pr_perror("Failed to create sem set");
		return -errno;
	}

	if (id != sem->desc->id) {
		pr_err("Failed to restore sem id (%d instead of %d)\n", id, sem->desc->id);
		return -EFAULT;
	}

	ret = semctl(id, sem->nsems, IPC_STAT, &semid);
	if (ret == -1) {
		pr_err("Failed to get sem stat structure\n");
		return -EFAULT;
	}

	semid.sem_perm.uid = sem->desc->uid;
	semid.sem_perm.gid = sem->desc->gid;

	ret = semctl(id, sem->nsems, IPC_SET, &semid);
	if (ret == -1) {
		pr_err("Failed to set sem uid and gid\n");
		return -EFAULT;
	}

	ret = prepare_ipc_sem_values(img, sem);
	if (ret < 0) {
		pr_err("Failed to update sem pages\n");
		return ret;
	}
	return 0;
}

static int prepare_ipc_sem(int pid)
{
	int ret;
	struct cr_img *img;

	pr_info("Restoring IPC semaphores sets\n");
	img = open_image(CR_FD_IPCNS_SEM, O_RSTR, pid);
	if (!img)
		return -1;

	while (1) {
		IpcSemEntry *sem;

		ret = pb_read_one_eof(img, &sem, PB_IPC_SEM);
		if (ret < 0) {
			ret = -EIO;
			goto err;
		}
		if (ret == 0)
			break;

		pr_info_ipc_sem_entry(sem);

		ret = prepare_ipc_sem_desc(img, sem);
		ipc_sem_entry__free_unpacked(sem, NULL);

		if (ret < 0) {
			pr_err("Failed to prepare semaphores set\n");
			goto err;
		}
	}

	close_image(img);
	return 0;

err:
	close_image(img);
	return ret;
}

static int prepare_ipc_msg_queue_messages(struct cr_img *img, const IpcMsgEntry *msq)
{
	IpcMsg *msg = NULL;
	int msg_nr = 0;
	int ret = 0;

	while (msg_nr < msq->qnum) {
		struct msgbuf {
			long mtype;
			char mtext[MSGMAX];
		} data;

		ret = pb_read_one(img, &msg, PB_IPCNS_MSG);
		if (ret <= 0)
			return -EIO;

		pr_info_ipc_msg(msg_nr, msg);

		if (msg->msize > MSGMAX) {
			ret = -1;
			pr_err("Unsupported message size: %d (MAX: %d)\n", msg->msize, MSGMAX);
			break;
		}

		ret = read_img_buf(img, data.mtext, round_up(msg->msize, sizeof(u64)));
		if (ret < 0) {
			pr_err("Failed to read IPC message data\n");
			break;
		}

		data.mtype = msg->mtype;
		ret = msgsnd(msq->desc->id, &data, msg->msize, IPC_NOWAIT);
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

static int prepare_ipc_msg_queue(struct cr_img *img, const IpcMsgEntry *msq)
{
	int ret, id;
	struct sysctl_req req[] = {
		{ "kernel/msg_next_id", &msq->desc->id, CTL_U32, CTL_FLAGS_IPC_EACCES_SKIP },
	};
	struct msqid_ds msqid;

	ret = sysctl_op(req, ARRAY_SIZE(req), CTL_WRITE, CLONE_NEWIPC);
	if (ret < 0) {
		pr_err("Failed to set desired IPC msg ID\n");
		return ret;
	}

	id = msgget(msq->desc->key, msq->desc->mode | IPC_CREAT | IPC_EXCL);
	if (id == -1) {
		pr_perror("Failed to create msg set");
		return -errno;
	}

	if (id != msq->desc->id) {
		pr_err("Failed to restore msg id (%d instead of %d)\n", id, msq->desc->id);
		return -EFAULT;
	}

	ret = msgctl(id, IPC_STAT, &msqid);
	if (ret == -1) {
		pr_err("Failed to get msq stat structure\n");
		return -EFAULT;
	}

	msqid.msg_perm.uid = msq->desc->uid;
	msqid.msg_perm.gid = msq->desc->gid;

	ret = msgctl(id, IPC_SET, &msqid);
	if (ret == -1) {
		pr_err("Failed to set msq queue uid and gid\n");
		return -EFAULT;
	}

	ret = prepare_ipc_msg_queue_messages(img, msq);
	if (ret < 0) {
		pr_err("Failed to update message queue messages\n");
		return ret;
	}
	return 0;
}

static int prepare_ipc_msg(int pid)
{
	int ret;
	struct cr_img *img;

	pr_info("Restoring IPC message queues\n");
	img = open_image(CR_FD_IPCNS_MSG, O_RSTR, pid);
	if (!img)
		return -1;

	while (1) {
		IpcMsgEntry *msq;

		ret = pb_read_one_eof(img, &msq, PB_IPCNS_MSG_ENT);
		if (ret < 0) {
			pr_err("Failed to read IPC messages queue\n");
			ret = -EIO;
			goto err;
		}
		if (ret == 0)
			break;

		pr_info_ipc_msg_entry(msq);

		ret = prepare_ipc_msg_queue(img, msq);
		ipc_msg_entry__free_unpacked(msq, NULL);

		if (ret < 0) {
			pr_err("Failed to prepare messages queue\n");
			goto err;
		}
	}

	close_image(img);
	return 0;
err:
	close_image(img);
	return ret;
}

static int restore_content(void *data, struct cr_img *img, const IpcShmEntry *shm)
{
	int ifd;
	ssize_t size, off;

	ifd = img_raw_fd(img);
	if (ifd < 0) {
		pr_err("Failed getting raw image fd\n");
		return -1;
	}
	size = round_up(shm->size, sizeof(u32));
	off = 0;
	do {
		ssize_t ret;

		ret = read(ifd, data + off, size - off);
		if (ret <= 0) {
			pr_perror("Failed to write IPC shared memory data");
			return (int)ret;
		}

		off += ret;
	} while (off < size);

	return 0;
}

static int prepare_ipc_shm_pages(struct cr_img *img, const IpcShmEntry *shm)
{
	int ret;
	void *data;

	data = shmat(shm->desc->id, NULL, 0);
	if (data == (void *)-1) {
		pr_perror("Failed to attach IPC shared memory");
		return -errno;
	}

	if (shm->has_in_pagemaps && shm->in_pagemaps)
		ret = restore_sysv_shmem_content(data, shm->size, shm->desc->id);
	else
		ret = restore_content(data, img, shm);

	if (shmdt(data)) {
		pr_perror("Failed to detach IPC shared memory");
		return -errno;
	}
	return ret;
}

static int prepare_ipc_shm_seg(struct cr_img *img, const IpcShmEntry *shm)
{
	int ret, id, hugetlb_flag = 0;
	struct sysctl_req req[] = {
		{ "kernel/shm_next_id", &shm->desc->id, CTL_U32, CTL_FLAGS_IPC_EACCES_SKIP },
	};
	struct shmid_ds shmid;

	if (collect_sysv_shmem(shm->desc->id, shm->size))
		return -1;

	ret = sysctl_op(req, ARRAY_SIZE(req), CTL_WRITE, CLONE_NEWIPC);
	if (ret < 0) {
		pr_err("Failed to set desired IPC shm ID\n");
		return ret;
	}

	if (shm->has_hugetlb_flag)
		hugetlb_flag = shm->hugetlb_flag;

	id = shmget(shm->desc->key, shm->size, hugetlb_flag | shm->desc->mode | IPC_CREAT | IPC_EXCL);
	if (id == -1) {
		pr_perror("Failed to create shm set");
		return -errno;
	}

	if (id != shm->desc->id) {
		pr_err("Failed to restore shm id (%d instead of %d)\n", id, shm->desc->id);
		return -EFAULT;
	}

	ret = shmctl(id, IPC_STAT, &shmid);
	if (ret == -1) {
		pr_err("Failed to get shm stat structure\n");
		return -EFAULT;
	}

	shmid.shm_perm.uid = shm->desc->uid;
	shmid.shm_perm.gid = shm->desc->gid;

	ret = shmctl(id, IPC_SET, &shmid);
	if (ret == -1) {
		pr_err("Failed to set shm uid and gid\n");
		return -EFAULT;
	}

	ret = prepare_ipc_shm_pages(img, shm);
	if (ret < 0) {
		pr_err("Failed to update shm pages\n");
		return ret;
	}
	return 0;
}

static int prepare_ipc_shm(int pid)
{
	int ret;
	struct cr_img *img;

	pr_info("Restoring IPC shared memory\n");
	img = open_image(CR_FD_IPCNS_SHM, O_RSTR, pid);
	if (!img)
		return -1;

	while (1) {
		IpcShmEntry *shm;

		ret = pb_read_one_eof(img, &shm, PB_IPC_SHM);
		if (ret < 0) {
			pr_err("Failed to read IPC shared memory segment\n");
			ret = -EIO;
			goto err;
		}
		if (ret == 0)
			break;

		pr_info_ipc_shm(shm);

		ret = prepare_ipc_shm_seg(img, shm);
		ipc_shm_entry__free_unpacked(shm, NULL);

		if (ret < 0) {
			pr_err("Failed to prepare shm segment\n");
			goto err;
		}
	}

	close_image(img);
	return 0;
err:
	close_image(img);
	return ret;
}

static int prepare_ipc_var(int pid)
{
	int ret;
	struct cr_img *img;
	IpcVarEntry *var;

	pr_info("Restoring IPC variables\n");
	img = open_image(CR_FD_IPC_VAR, O_RSTR, pid);
	if (!img)
		return -1;

	ret = pb_read_one(img, &var, PB_IPC_VAR);
	close_image(img);
	if (ret <= 0) {
		pr_err("Failed to read IPC namespace variables\n");
		return -EFAULT;
	}

	ret = ipc_sysctl_req(var, CTL_WRITE);
	ipc_var_entry__free_unpacked(var, NULL);

	if (ret < 0) {
		pr_err("Failed to prepare IPC namespace variables\n");
		return -EFAULT;
	}

	return 0;
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

struct ns_desc ipc_ns_desc = NS_DESC_ENTRY(CLONE_NEWIPC, "ipc");
