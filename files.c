#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#include <linux/limits.h>
#include <linux/major.h>

#include <sys/types.h>
#include <sys/prctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdlib.h>

#include "crtools.h"

#include "files.h"
#include "file-ids.h"
#include "files-reg.h"
#include "image.h"
#include "list.h"
#include "util.h"
#include "util-net.h"
#include "lock.h"
#include "sockets.h"
#include "pstree.h"
#include "tty.h"
#include "pipes.h"
#include "fifo.h"
#include "eventfd.h"
#include "eventpoll.h"
#include "fsnotify.h"
#include "signalfd.h"

#include "parasite.h"
#include "parasite-syscall.h"

#include "protobuf.h"
#include "protobuf/fs.pb-c.h"

#define FDESC_HASH_SIZE	64
static struct list_head file_desc_hash[FDESC_HASH_SIZE];

int prepare_shared_fdinfo(void)
{
	int i;

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
	if (list_empty(&d->fd_info_head)) {
		pr_err("Empty list on file desc id %#x\n", d->id);
		BUG();
	}

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

static u32 make_gen_id(const struct fd_parms *p)
{
	return ((u32)p->stat.st_dev) ^ ((u32)p->stat.st_ino) ^ ((u32)p->pos);
}

int do_dump_gen_file(struct fd_parms *p, int lfd,
		const struct fdtype_ops *ops, const int fdinfo)
{
	FdinfoEntry e = FDINFO_ENTRY__INIT;
	int ret = -1;

	e.type	= ops->type;
	e.id	= make_gen_id(p);
	e.fd	= p->fd;
	e.flags = p->fd_flags;

	ret = fd_id_generate(p->pid, &e);
	if (ret == 1) /* new ID generated */
		ret = ops->dump(lfd, e.id, p);

	if (ret < 0)
		return -1;

	pr_info("fdinfo: type: 0x%2x flags: %#o/%#o pos: 0x%8lx fd: %d\n",
		ops->type, p->flags, (int)p->fd_flags, p->pos, p->fd);

	return pb_write_one(fdinfo, &e, PB_FDINFO);
}

static int fill_fd_params(struct parasite_ctl *ctl, int fd, int lfd,
				struct fd_opts *opts, struct fd_parms *p)
{
	if (fstat(lfd, &p->stat) < 0) {
		pr_perror("Can't stat fd %d\n", lfd);
		return -1;
	}

	p->ctl		= ctl;
	p->fd		= fd;
	p->pos		= lseek(lfd, 0, SEEK_CUR);
	p->flags	= fcntl(lfd, F_GETFL);
	p->pid		= ctl->pid;
	p->fd_flags	= opts->flags;

	fown_entry__init(&p->fown);

	pr_info("%d fdinfo %d: pos: 0x%16lx flags: %16o/%#x\n",
		ctl->pid, fd, p->pos, p->flags, (int)p->fd_flags);

	p->fown.signum = fcntl(lfd, F_GETSIG, 0);
	if (p->fown.signum < 0) {
		pr_perror("Can't get owner signum on %d\n", lfd);
		return -1;
	}

	if (opts->fown.pid == 0)
		return 0;

	p->fown.pid	 = opts->fown.pid;
	p->fown.pid_type = opts->fown.pid_type;
	p->fown.uid	 = opts->fown.uid;
	p->fown.euid	 = opts->fown.euid;

	return 0;
}

static int dump_unsupp_fd(const struct fd_parms *p)
{
	pr_err("Can't dump file %d of that type [%#x]\n",
			p->fd, p->stat.st_mode);
	return -1;
}

static int dump_chrdev(struct fd_parms *p, int lfd, const int fdinfo)
{
	int maj = major(p->stat.st_rdev);

	switch (maj) {
	case MEM_MAJOR:
		return dump_reg_file(p, lfd, fdinfo);
	case TTYAUX_MAJOR:
	case UNIX98_PTY_MASTER_MAJOR ... (UNIX98_PTY_MASTER_MAJOR + UNIX98_PTY_MAJOR_COUNT - 1):
	case UNIX98_PTY_SLAVE_MAJOR:
		return dump_tty(p, lfd, fdinfo);
	}

	return dump_unsupp_fd(p);
}

#ifndef PIPEFS_MAGIC
#define PIPEFS_MAGIC	0x50495045
#endif

static int dump_one_file(struct parasite_ctl *ctl, int fd, int lfd, struct fd_opts *opts,
		       const int fdinfo)
{
	struct fd_parms p;
	struct statfs statfs;

	if (fill_fd_params(ctl, fd, lfd, opts, &p) < 0) {
		pr_perror("Can't get stat on %d", fd);
		return -1;
	}

	if (S_ISSOCK(p.stat.st_mode))
		return dump_socket(&p, lfd, fdinfo);

	if (S_ISCHR(p.stat.st_mode))
		return dump_chrdev(&p, lfd, fdinfo);

	if (fstatfs(lfd, &statfs)) {
		pr_perror("Can't obtain statfs on fd %d\n", fd);
		return -1;
	}

	if (is_anon_inode(&statfs)) {
		if (is_eventfd_link(lfd))
			return dump_eventfd(&p, lfd, fdinfo);
		else if (is_eventpoll_link(lfd))
			return dump_eventpoll(&p, lfd, fdinfo);
		else if (is_inotify_link(lfd))
			return dump_inotify(&p, lfd, fdinfo);
		else if (is_fanotify_link(lfd))
			return dump_fanotify(&p, lfd, fdinfo);
		else if (is_signalfd_link(lfd))
			return dump_signalfd(&p, lfd, fdinfo);
		else
			return dump_unsupp_fd(&p);
	}

	if (S_ISREG(p.stat.st_mode) || S_ISDIR(p.stat.st_mode))
		return dump_reg_file(&p, lfd, fdinfo);

	if (S_ISFIFO(p.stat.st_mode)) {
		if (statfs.f_type == PIPEFS_MAGIC)
			return dump_pipe(&p, lfd, fdinfo);
		else
			return dump_fifo(&p, lfd, fdinfo);
	}

	return dump_unsupp_fd(&p);
}

int dump_task_files_seized(struct parasite_ctl *ctl, struct pstree_item *item,
		struct parasite_drain_fd *dfds)
{
	int *lfds, fdinfo;
	struct fd_opts *opts;
	int i, ret = -1;

	pr_info("\n");
	pr_info("Dumping opened files (pid: %d)\n", ctl->pid);
	pr_info("----------------------------------------\n");

	lfds = xmalloc(dfds->nr_fds * sizeof(int));
	if (!lfds)
		goto err;

	opts = xmalloc(dfds->nr_fds * sizeof(struct fd_opts));
	if (!opts)
		goto err1;

	ret = parasite_drain_fds_seized(ctl, dfds, lfds, opts);
	if (ret)
		goto err2;

	fdinfo = open_image(CR_FD_FDINFO, O_DUMP, item->ids->files_id);
	if (fdinfo < 0)
		goto err2;

	for (i = 0; i < dfds->nr_fds; i++) {
		ret = dump_one_file(ctl, dfds->fds[i], lfds[i], opts + i, fdinfo);
		close(lfds[i]);
		if (ret)
			break;
	}

	close(fdinfo);

	pr_info("----------------------------------------\n");
err2:
	xfree(opts);
err1:
	xfree(lfds);
err:
	return ret;
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

static struct list_head *select_ps_list(struct file_desc *desc, struct rst_info *ri)
{
	if (desc->ops->select_ps_list)
		return desc->ops->select_ps_list(desc, ri);
	else
		return &ri->fds;
}

static int collect_fd(int pid, FdinfoEntry *e, struct rst_info *rst_info)
{
	struct fdinfo_list_entry *le, *new_le;
	struct file_desc *fdesc;

	pr_info("Collect fdinfo pid=%d fd=%d id=0x%16x\n",
		pid, e->fd, e->id);

	new_le = shmalloc(sizeof(*new_le));
	if (!new_le)
		return -1;

	futex_init(&new_le->real_pid);
	new_le->pid = pid;
	new_le->fe = e;

	fdesc = find_file_desc(e);
	if (fdesc == NULL) {
		pr_err("No file for fd %d id %d\n", e->fd, e->id);
		return -1;
	}

	list_for_each_entry(le, &fdesc->fd_info_head, desc_list) {
		if (le->pid > new_le->pid)
			break;
	}

	list_add_tail(&new_le->desc_list, &le->desc_list);
	new_le->desc = fdesc;
	list_add_tail(&new_le->ps_list, select_ps_list(fdesc, rst_info));

	return 0;
}

int prepare_ctl_tty(int pid, struct rst_info *rst_info, u32 ctl_tty_id)
{
	FdinfoEntry *e;

	if (!ctl_tty_id)
		return 0;

	pr_info("Requesting for ctl tty %#x into service fd\n", ctl_tty_id);

	e = xmalloc(sizeof(*e));
	if (!e)
		return -1;

	fdinfo_entry__init(e);

	e->id		= ctl_tty_id;
	e->fd		= get_service_fd(CTL_TTY_OFF);
	e->type		= FD_TYPES__TTY;

	if (collect_fd(pid, e, rst_info)) {
		xfree(e);
		return -1;
	}

	return 0;
}

int prepare_fd_pid(struct pstree_item *item)
{
	int fdinfo_fd, ret = 0;
	pid_t pid = item->pid.virt;
	struct rst_info *rst_info = item->rst;

	INIT_LIST_HEAD(&rst_info->fds);
	INIT_LIST_HEAD(&rst_info->eventpoll);
	INIT_LIST_HEAD(&rst_info->tty_slaves);

	if (!fdinfo_per_id) {
		fdinfo_fd = open_image_ro(CR_FD_FDINFO, pid);
		if (fdinfo_fd < 0) {
			if (errno == ENOENT)
				return 0;
			return -1;
		}
	} else {
		if (item->ids == NULL) /* zombie */
			return 0;

		if (item->rst->fdt && item->rst->fdt->pid != item->pid.virt)
			return 0;

		fdinfo_fd = open_image_ro(CR_FD_FDINFO, item->ids->files_id);
		if (fdinfo_fd < 0)
			return -1;
	}

	while (1) {
		FdinfoEntry *e;

		ret = pb_read_one_eof(fdinfo_fd, &e, PB_FDINFO);
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

int send_fd_to_peer(int fd, struct fdinfo_list_entry *fle, int sock)
{
	struct sockaddr_un saddr;
	int len;

	pr_info("\t\tWait fdinfo pid=%d fd=%d\n", fle->pid, fle->fe->fd);
	futex_wait_while(&fle->real_pid, 0);
	transport_name_gen(&saddr, &len,
			futex_get(&fle->real_pid), fle->fe->fd);
	pr_info("\t\tSend fd %d to %s\n", fd, saddr.sun_path + 1);
	return send_fd(sock, &saddr, len, fd);
}

static int send_fd_to_self(int fd, struct fdinfo_list_entry *fle, int *sock)
{
	int dfd = fle->fe->fd;

	if (fd == dfd)
		return 0;

	pr_info("\t\t\tGoing to dup %d into %d\n", fd, dfd);
	if (move_img_fd(sock, dfd))
		return -1;

	if (dup2(fd, dfd) != dfd) {
		pr_perror("Can't dup local fd %d -> %d", fd, dfd);
		return -1;
	}

	fcntl(dfd, F_SETFD, fle->fe->flags);
	return 0;
}

static int post_open_fd(int pid, struct fdinfo_list_entry *fle)
{
	struct file_desc *d = fle->desc;

	if (!d->ops->post_open)
		return 0;

	if (is_service_fd(fle->fe->fd, CTL_TTY_OFF))
		return d->ops->post_open(d, fle->fe->fd);

	if (fle != file_master(d))
		return 0;

	return d->ops->post_open(d, fle->fe->fd);
}


static int serve_out_fd(int pid, int fd, struct file_desc *d)
{
	int sock, ret;
	struct fdinfo_list_entry *fle;

	sock = socket(PF_UNIX, SOCK_DGRAM, 0);
	if (sock < 0) {
		pr_perror("Can't create socket");
		return -1;
	}

	pr_info("\t\tCreate fd for %d\n", fd);

	list_for_each_entry(fle, &d->fd_info_head, desc_list) {
		if (pid == fle->pid)
			ret = send_fd_to_self(fd, fle, &sock);
		else
			ret = send_fd_to_peer(fd, fle, sock);

		if (ret) {
			pr_err("Can't sent fd %d to %d\n", fd, fle->pid);
			return -1;
		}
	}

	close(sock);
	return 0;
}

static int open_fd(int pid, struct fdinfo_list_entry *fle)
{
	struct file_desc *d = fle->desc;
	int new_fd;

	if (fle != file_master(d))
		return 0;

	new_fd = d->ops->open(d);
	if (new_fd < 0)
		return -1;

	if (reopen_fd_as(fle->fe->fd, new_fd))
		return -1;

	fcntl(fle->fe->fd, F_SETFD, fle->fe->flags);

	return serve_out_fd(pid, fle->fe->fd, d);
}

static int receive_fd(int pid, struct fdinfo_list_entry *fle)
{
	int tmp;
	struct fdinfo_list_entry *flem;

	flem = file_master(fle->desc);
	if (flem->pid == pid)
		return 0;

	pr_info("\tReceive fd for %d\n", fle->fe->fd);

	tmp = recv_fd(fle->fe->fd);
	if (tmp < 0) {
		pr_err("Can't get fd %d\n", tmp);
		return -1;
	}
	close(fle->fe->fd);

	if (reopen_fd_as(fle->fe->fd, tmp) < 0)
		return -1;

	fcntl(tmp, F_SETFD, fle->fe->flags);
	return 0;
}

struct fd_open_state {
	char *name;
	int (*cb)(int, struct fdinfo_list_entry *);
};

static struct fd_open_state states[] = {
	{ "prepare",		open_transport_fd, },
	{ "create",		open_fd, },
	{ "receive",		receive_fd, },
	{ "post_create",	post_open_fd, },
};

static int open_fdinfo(int pid, struct fdinfo_list_entry *fle, int state)
{
	pr_info("\tRestoring fd %d (state -> %s)\n",
			fle->fe->fd, states[state].name);
	return states[state].cb(pid, fle);
}

static int open_fdinfos(int pid, struct list_head *list, int state)
{
	int ret = 0;
	struct fdinfo_list_entry *fle;

	list_for_each_entry(fle, list, ps_list) {
		ret = open_fdinfo(pid, fle, state);
		if (ret)
			break;
	}

	return ret;
}

int close_old_fds(struct pstree_item *me)
{
	DIR *dir;
	struct dirent *de;
	int fd, ret;

	dir = opendir_proc(getpid(), "fd");
	if (dir == NULL)
		return -1;

	while ((de = readdir(dir))) {
		if (dir_dots(de))
			continue;

		ret = sscanf(de->d_name, "%d", &fd);
		if (ret != 1) {
			pr_err("Can't parse %s\n", de->d_name);
			return -1;
		}

		if ((!is_any_service_fd(fd)) && (dirfd(dir) != fd))
			close_safe(&fd);
	}

	closedir(dir);
	close_pid_proc();

	return 0;
}

int prepare_fds(struct pstree_item *me)
{
	u32 ret = 0;
	int state;

	pr_info("Opening fdinfo-s\n");

	if (me->rst->fdt) {
		struct fdt *fdt = me->rst->fdt;

		/*
		 * Wait all tasks, who share a current fd table.
		 * We should be sure, that nobody use any file
		 * descriptor while fdtable is being restored.
		 */
		futex_inc_and_wake(&fdt->fdt_lock);
		futex_wait_while_lt(&fdt->fdt_lock, fdt->nr);

		if (fdt->pid != me->pid.virt) {
			pr_info("File descriptor talbe is shared with %d\n", fdt->pid);
			futex_wait_until(&fdt->fdt_lock, fdt->nr + 1);
			goto out;
		}
	}

	for (state = 0; state < ARRAY_SIZE(states); state++) {
		ret = open_fdinfos(me->pid.virt, &me->rst->fds, state);
		if (ret)
			break;

		/*
		 * Now handle TTYs. Slaves are delayed to be sure masters
		 * are already opened.
		 */
		ret = open_fdinfos(me->pid.virt, &me->rst->tty_slaves, state);
		if (ret)
			break;

		/*
		 * The eventpoll descriptors require all the other ones
		 * to be already restored, thus we store them in a separate
		 * list and restore at the very end.
		 */
		ret = open_fdinfos(me->pid.virt, &me->rst->eventpoll, state);
		if (ret)
			break;
	}

	if (me->rst->fdt)
		futex_inc_and_wake(&me->rst->fdt->fdt_lock);
out:
	tty_fini_fds();
	return ret;
}

int prepare_fs(int pid)
{
	int ifd, cwd, ret = -1;
	FsEntry *fe;

	ifd = open_image_ro(CR_FD_FS, pid);
	if (ifd < 0)
		return -1;

	if (pb_read_one(ifd, &fe, PB_FS) < 0) {
		close_safe(&ifd);
		return -1;
	}

	cwd = open_reg_by_id(fe->cwd_id);
	if (cwd < 0) {
		close_safe(&ifd);
		goto err;
	}

	if (fchdir(cwd) < 0) {
		pr_perror("Can't change root");
		goto close;
	}

	/*
	 * FIXME: restore task's root. Don't want to do it now, since
	 * it's not yet clean how we're going to resolve tasks' paths
	 * relative to the dumper/restorer and all this logic is likely
	 * to be hidden in a couple of calls (open_fe_fd is one od them)
	 * but for chroot there's no fchroot call, we have to chroot
	 * by path thus exposing this (yet unclean) logic here.
	 */

	if (fe->has_umask) {
		pr_info("Restoring umask to %o\n", fe->umask);
		umask(fe->umask);
	}

	ret = 0;
close:
	close_safe(&cwd);
	close_safe(&ifd);
err:
	fs_entry__free_unpacked(fe, NULL);
	return ret;
}

int get_filemap_fd(int pid, VmaEntry *vma_entry)
{
	return open_reg_by_id(vma_entry->shmid);
}

int shared_fdt_prepare(struct pstree_item *item)
{
	struct pstree_item *parent = item->parent;
	struct fdt *fdt;

	if (!parent->rst->fdt) {
		fdt = shmalloc(sizeof(*item->rst->fdt));
		if (fdt == NULL)
			return -1;

		parent->rst->fdt = fdt;

		futex_init(&fdt->fdt_lock);
		fdt->nr = 1;
		fdt->pid = parent->pid.virt;
	} else
		fdt = parent->rst->fdt;

	item->rst->fdt = fdt;
	item->rst->service_fd_id = fdt->nr;
	fdt->nr++;
	if (fdt->pid > item->pid.virt)
		fdt->pid = item->pid.virt;

	return 0;
}
