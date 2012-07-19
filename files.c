#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#include <linux/limits.h>

#include <sys/types.h>
#include <sys/prctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdlib.h>

#include "crtools.h"

#include "files.h"
#include "files-reg.h"
#include "image.h"
#include "list.h"
#include "util.h"
#include "util-net.h"
#include "lock.h"
#include "sockets.h"
#include "pstree.h"

#include "protobuf.h"
#include "protobuf/fs.pb-c.h"

static struct fdinfo_list_entry *fdinfo_list;
static int nr_fdinfo_list;

#define FDESC_HASH_SIZE	64
static struct list_head file_desc_hash[FDESC_HASH_SIZE];

#define FDINFO_POOL_SIZE	(4 * 4096)

int prepare_shared_fdinfo(void)
{
	int i;

	fdinfo_list = mmap(NULL, FDINFO_POOL_SIZE,
			PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANON, 0, 0);
	if (fdinfo_list == MAP_FAILED) {
		pr_perror("Can't map fdinfo_list");
		return -1;
	}

	for (i = 0; i < FDESC_HASH_SIZE; i++)
		INIT_LIST_HEAD(&file_desc_hash[i]);

	return 0;
}

void file_desc_add(struct file_desc *d, u32 id, struct file_desc_ops *ops)
{
	d->id = id;
	d->ops = ops;
	INIT_LIST_HEAD(&d->fd_info_head);

	list_add_tail(&d->hash, &file_desc_hash[id % FDESC_HASH_SIZE]);
}

struct file_desc *find_file_desc_raw(int type, u32 id)
{
	struct file_desc *d;
	struct list_head *chain;

	chain = &file_desc_hash[id % FDESC_HASH_SIZE];
	list_for_each_entry(d, chain, hash)
		if (d->ops->type == type && d->id == id)
			return d;

	return NULL;
}

static inline struct file_desc *find_file_desc(FdinfoEntry *fe)
{
	return find_file_desc_raw(fe->type, fe->id);
}

struct fdinfo_list_entry *file_master(struct file_desc *d)
{
	BUG_ON(list_empty(&d->fd_info_head));
	return list_first_entry(&d->fd_info_head,
			struct fdinfo_list_entry, desc_list);
}

void show_saved_files(void)
{
	int i;
	struct file_desc *fd;

	pr_info("File descs:\n");
	for (i = 0; i < FDESC_HASH_SIZE; i++)
		list_for_each_entry(fd, &file_desc_hash[i], hash) {
			struct fdinfo_list_entry *le;

			pr_info(" `- type %d ID %#x\n", fd->ops->type, fd->id);
			list_for_each_entry(le, &fd->fd_info_head, desc_list)
				pr_info("   `- FD %d pid %d\n", le->fe->fd, le->pid);
		}
}

int restore_fown(int fd, FownEntry *fown)
{
	struct f_owner_ex owner;
	uid_t uids[3];
	pid_t pid = getpid();

	if (fown->signum) {
		if (fcntl(fd, F_SETSIG, fown->signum)) {
			pr_perror("%d: Can't set signal", pid);
			return -1;
		}
	}

	/* May be untouched */
	if (!fown->pid)
		return 0;

	if (getresuid(&uids[0], &uids[1], &uids[2])) {
		pr_perror("%d: Can't get current UIDs", pid);
		return -1;
	}

	if (setresuid(fown->uid, fown->euid, uids[2])) {
		pr_perror("%d: Can't set UIDs", pid);
		return -1;
	}

	owner.type = fown->pid_type;
	owner.pid = fown->pid;

	if (fcntl(fd, F_SETOWN_EX, &owner)) {
		pr_perror("%d: Can't setup %d file owner pid",
			  pid, fd);
		return -1;
	}

	if (setresuid(uids[0], uids[1], uids[2])) {
		pr_perror("%d: Can't revert UIDs back", pid);
		return -1;
	}

	return 0;
}

int rst_file_params(int fd, FownEntry *fown, int flags)
{
	if (set_fd_flags(fd, flags) < 0)
		return -1;
	if (restore_fown(fd, fown) < 0)
		return -1;
	return 0;
}

static int collect_fd(int pid, FdinfoEntry *e, struct rst_info *rst_info)
{
	struct fdinfo_list_entry *l, *le = &fdinfo_list[nr_fdinfo_list];
	struct file_desc *fdesc;

	pr_info("Collect fdinfo pid=%d fd=%d id=0x%16x\n",
		pid, e->fd, e->id);

	nr_fdinfo_list++;
	if ((nr_fdinfo_list) * sizeof(struct fdinfo_list_entry) >= FDINFO_POOL_SIZE) {
		pr_err("OOM storing fdinfo_list_entries\n");
		return -1;
	}

	le->pid = pid;
	futex_init(&le->real_pid);
	le->fe = e;

	fdesc = find_file_desc(e);
	if (fdesc == NULL) {
		pr_err("No file for fd %d id %d\n", e->fd, e->id);
		return -1;
	}

	list_for_each_entry(l, &fdesc->fd_info_head, desc_list)
		if (l->pid > le->pid)
			break;

	list_add_tail(&le->desc_list, &l->desc_list);
	le->desc = fdesc;

	if (unlikely(le->fe->type == FD_TYPES__EVENTPOLL))
		list_add_tail(&le->ps_list, &rst_info->eventpoll);
	else
		list_add_tail(&le->ps_list, &rst_info->fds);
	return 0;
}

int prepare_fd_pid(int pid, struct rst_info *rst_info)
{
	int fdinfo_fd, ret = 0;

	INIT_LIST_HEAD(&rst_info->fds);
	INIT_LIST_HEAD(&rst_info->eventpoll);

	fdinfo_fd = open_image_ro(CR_FD_FDINFO, pid);
	if (fdinfo_fd < 0) {
		if (errno == ENOENT)
			return 0;
		else
			return -1;
	}

	while (1) {
		FdinfoEntry *e;

		ret = pb_read_eof(fdinfo_fd, &e, fdinfo_entry);
		if (ret <= 0)
			break;

		ret = collect_fd(pid, e, rst_info);
		if (ret < 0) {
			fdinfo_entry__free_unpacked(e, NULL);
			break;
		}
	}

	close(fdinfo_fd);
	return ret;
}

#define SETFL_MASK (O_APPEND | O_ASYNC | O_NONBLOCK | O_NDELAY | O_DIRECT | O_NOATIME)
int set_fd_flags(int fd, int flags)
{
	int ret;

	ret = fcntl(fd, F_GETFL, 0);
	if (ret < 0)
		goto err;

	flags = (SETFL_MASK & flags) | (ret & ~SETFL_MASK);

	ret = fcntl(fd, F_SETFL, flags);
	if (ret < 0)
		goto err;
	return 0;

err:
	pr_perror("fcntl call on fd %d (flags %x) failed", fd, flags);
	return -1;
}

static void transport_name_gen(struct sockaddr_un *addr, int *len,
		int pid, int fd)
{
	addr->sun_family = AF_UNIX;
	snprintf(addr->sun_path, UNIX_PATH_MAX, "x/crtools-fd-%d-%d", pid, fd);
	*len = SUN_LEN(addr);
	*addr->sun_path = '\0';
}

static int should_open_transport(FdinfoEntry *fe, struct file_desc *fd)
{
	if (fd->ops->want_transport)
		return fd->ops->want_transport(fe, fd);
	else
		return 0;
}

static int open_transport_fd(int pid, struct fdinfo_list_entry *fle)
{
	struct fdinfo_list_entry *flem;
	struct sockaddr_un saddr;
	int sock;
	int ret, sun_len;

	flem = file_master(fle->desc);

	if (flem->pid == pid) {
		if (flem->fe->fd != fle->fe->fd)
			/* dup-ed file. Will be opened in the open_fd */
			return 0;

		if (!should_open_transport(fle->fe, fle->desc))
			/* pure master file */
			return 0;

		/*
		 * some master file, that wants a transport, e.g.
		 * a pipe or unix socket pair 'slave' end
		 */
	}

	transport_name_gen(&saddr, &sun_len, getpid(), fle->fe->fd);

	pr_info("\t\tCreate transport fd %s\n", saddr.sun_path + 1);


	sock = socket(PF_UNIX, SOCK_DGRAM, 0);
	if (sock < 0) {
		pr_perror("Can't create socket");
		return -1;
	}
	ret = bind(sock, &saddr, sun_len);
	if (ret < 0) {
		pr_perror("Can't bind unix socket %s", saddr.sun_path + 1);
		return -1;
	}

	ret = reopen_fd_as(fle->fe->fd, sock);
	if (ret < 0)
		return -1;

	pr_info("\t\tWake up fdinfo pid=%d fd=%d\n", fle->pid, fle->fe->fd);
	futex_set_and_wake(&fle->real_pid, getpid());

	return 0;
}

int send_fd_to_peer(int fd, struct fdinfo_list_entry *fle, int tsk)
{
	struct sockaddr_un saddr;
	int len;

	pr_info("\t\tWait fdinfo pid=%d fd=%d\n", fle->pid, fle->fe->fd);
	futex_wait_while(&fle->real_pid, 0);
	transport_name_gen(&saddr, &len,
			futex_get(&fle->real_pid), fle->fe->fd);
	pr_info("\t\tSend fd %d to %s\n", fd, saddr.sun_path + 1);
	return send_fd(tsk, &saddr, len, fd);
}

static int open_fd(int pid, FdinfoEntry *fe, struct file_desc *d)
{
	int tmp;
	int sock;
	struct fdinfo_list_entry *fle;

	fle = file_master(d);
	if ((fle->pid != pid) || (fe->fd != fle->fe->fd))
		return 0;

	tmp = d->ops->open(d);
	if (tmp < 0)
		return -1;

	if (reopen_fd_as(fe->fd, tmp))
		return -1;

	fcntl(fe->fd, F_SETFD, fe->flags);

	sock = socket(PF_UNIX, SOCK_DGRAM, 0);
	if (sock < 0) {
		pr_perror("Can't create socket");
		return -1;
	}

	pr_info("\t\tCreate fd for %d\n", fe->fd);

	list_for_each_entry(fle, &d->fd_info_head, desc_list) {
		if (pid == fle->pid) {
			pr_info("\t\t\tGoing to dup %d into %d\n", fe->fd, fle->fe->fd);
			if (fe->fd == fle->fe->fd)
				continue;

			if (move_img_fd(&sock, fle->fe->fd))
				return -1;

			if (dup2(fe->fd, fle->fe->fd) != fle->fe->fd) {
				pr_perror("Can't dup local fd %d -> %d",
						fe->fd, fle->fe->fd);
				return -1;
			}

			fcntl(fle->fe->fd, F_SETFD, fle->fe->flags);

			continue;
		}

		if (send_fd_to_peer(fe->fd, fle, sock)) {
			pr_perror("Can't send file descriptor");
			return -1;
		}
	}

	close(sock);
	return 0;
}

static int receive_fd(int pid, FdinfoEntry *fe, struct file_desc *d)
{
	int tmp;
	struct fdinfo_list_entry *fle;

	fle = file_master(d);

	if (fle->pid == pid)
		return 0;

	pr_info("\tReceive fd for %d\n", fe->fd);

	tmp = recv_fd(fe->fd);
	if (tmp < 0) {
		pr_err("Can't get fd %d\n", tmp);
		return -1;
	}
	close(fe->fd);

	if (reopen_fd_as(fe->fd, tmp) < 0)
		return -1;

	fcntl(tmp, F_SETFD, fe->flags);
	return 0;
}

static char *fdinfo_states[FD_STATE_MAX] = {
	[FD_STATE_PREP]		= "prepare",
	[FD_STATE_CREATE]	= "create",
	[FD_STATE_RECV]		= "receive",
};

static int open_fdinfo(int pid, struct fdinfo_list_entry *fle, int state)
{
	int ret = 0;

	BUG_ON(state >= FD_STATE_MAX);
	pr_info("\tRestoring fd %d (state -> %s)\n",
			fle->fe->fd, fdinfo_states[state]);

	switch (state) {
	case FD_STATE_PREP:
		ret = open_transport_fd(pid, fle);
		break;
	case FD_STATE_CREATE:
		ret = open_fd(pid, fle->fe, fle->desc);
		break;
	case FD_STATE_RECV:
		ret = receive_fd(pid, fle->fe, fle->desc);
		break;
	}

	return ret;
}

static int close_old_fds(struct pstree_item *me)
{
	/*
	 * FIXME -- The existing test_init implementation uses system()
	 * which in turn doesn't work when all fds are closed
	 */
	if (me->pid.virt == 1)
		return 0;

	/* FIXME -- wait for nextfd syscall (or read proc) */
	close(0);
	close(1);
	close(2);
	close(255); /* bash */
	return 0;
}

int prepare_fds(struct pstree_item *me)
{
	u32 ret;
	int state;
	struct fdinfo_list_entry *fle;

	ret = close_old_fds(me);
	if (ret)
		return ret;

	pr_info("Opening fdinfo-s\n");

	for (state = 0; state < FD_STATE_MAX; state++) {
		list_for_each_entry(fle, &me->rst->fds, ps_list) {
			ret = open_fdinfo(me->pid.virt, fle, state);
			if (ret)
				goto done;
		}

		/*
		 * The eventpoll descriptors require all the other ones
		 * to be already restored, thus we store them in a separate
		 * list and restore at the very end.
		 */
		list_for_each_entry(fle, &me->rst->eventpoll, ps_list) {
			ret = open_fdinfo(me->pid.virt, fle, state);
			if (ret)
				goto done;
		}
	}

	ret = run_unix_connections();
done:
	return ret;
}

int prepare_fs(int pid)
{
	int ifd, cwd, ret = -1;
	FsEntry *fe;

	ifd = open_image_ro(CR_FD_FS, pid);
	if (ifd < 0)
		return -1;

	if (pb_read(ifd, &fe, fs_entry) < 0)
		return -1;

	cwd = open_reg_by_id(fe->cwd_id);
	if (cwd < 0)
		goto err;

	if (fchdir(cwd) < 0) {
		pr_perror("Can't change root");
		goto err;
	}

	close(cwd);
	close(ifd);

	/*
	 * FIXME: restore task's root. Don't want to do it now, since
	 * it's not yet clean how we're going to resolve tasks' paths
	 * relative to the dumper/restorer and all this logic is likely
	 * to be hidden in a couple of calls (open_fe_fd is one od them)
	 * but for chroot there's no fchroot call, we have to chroot
	 * by path thus exposing this (yet unclean) logic here.
	 */

	ret = 0;
err:
	fs_entry__free_unpacked(fe, NULL);
	return ret;
}

int get_filemap_fd(int pid, VmaEntry *vma_entry)
{
	return open_reg_by_id(vma_entry->shmid);
}
