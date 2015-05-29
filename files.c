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

#include "files.h"
#include "file-ids.h"
#include "files-reg.h"
#include "file-lock.h"
#include "image.h"
#include "list.h"
#include "util.h"
#include "util-pie.h"
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
#include "namespaces.h"
#include "tun.h"
#include "timerfd.h"
#include "imgset.h"
#include "fs-magic.h"
#include "proc_parse.h"
#include "cr_options.h"

#include "parasite.h"
#include "parasite-syscall.h"

#include "protobuf.h"
#include "protobuf/fs.pb-c.h"
#include "protobuf/ext-file.pb-c.h"

#include "plugin.h"

#define FDESC_HASH_SIZE	64
static struct hlist_head file_desc_hash[FDESC_HASH_SIZE];

int prepare_shared_fdinfo(void)
{
	int i;

	for (i = 0; i < FDESC_HASH_SIZE; i++)
		INIT_HLIST_HEAD(&file_desc_hash[i]);

	return 0;
}

void file_desc_init(struct file_desc *d, u32 id, struct file_desc_ops *ops)
{
	INIT_LIST_HEAD(&d->fd_info_head);
	INIT_HLIST_NODE(&d->hash);

	d->id	= id;
	d->ops	= ops;
}

int file_desc_add(struct file_desc *d, u32 id, struct file_desc_ops *ops)
{
	file_desc_init(d, id, ops);
	hlist_add_head(&d->hash, &file_desc_hash[id % FDESC_HASH_SIZE]);
	return 0; /* this is to make tail-calls in collect_one_foo look nice */
}

struct file_desc *find_file_desc_raw(int type, u32 id)
{
	struct file_desc *d;
	struct hlist_head *chain;

	chain = &file_desc_hash[id % FDESC_HASH_SIZE];
	hlist_for_each_entry(d, chain, hash)
		if (d->ops->type == type && d->id == id)
			return d;

	return NULL;
}

static inline struct file_desc *find_file_desc(FdinfoEntry *fe)
{
	return find_file_desc_raw(fe->type, fe->id);
}

/*
 * A file may be shared between several file descriptors. E.g
 * when doing a fork() every fd of a forker and respective fds
 * of the child have such. Another way of getting shared files
 * is by dup()-ing them or sending them via unix sockets in
 * SCM_RIGHTS message.
 *
 * We restore this type of things in 3 steps (states[] below)
 *
 * 1. Prepare step.
 *    Select which task will create the file (open() one, or
 *    call any other syscall for than (socket, pipe, etc.). All
 *    the others, that share one, create unix sockets under the
 *    respective file descriptor (transport socket).
 * 2. Open step.
 *    The one who creates the file (the 'master') creates one,
 *    then creates one more unix socket (transport) and sends the
 *    created file over this socket to the other recepients.
 * 3. Receive step.
 *    Those, who wait for the file to appear, receive one via
 *    the transport socket, then close the socket and dup() the
 *    received file descriptor into its place.
 *
 * There's the 4th step in the states[] array -- the post_open
 * one. This one is not about file-sharing resolving, but about
 * doing something with a file using it's 'desired' fd. The
 * thing is that while going the 3-step process above, the file
 * may appear in variuos places in the task's fd table, and if
 * we want to do something with it's _final_ descriptor value,
 * we should wait for it to appear there. So the post_open is
 * called when the file is finally set into its place.
 */

struct fdinfo_list_entry *file_master(struct file_desc *d)
{
	if (list_empty(&d->fd_info_head)) {
		pr_err("Empty list on file desc id %#x(%d)\n", d->id,
				d->ops ? d->ops->type : -1);
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
		hlist_for_each_entry(fd, &file_desc_hash[i], hash) {
			struct fdinfo_list_entry *le;

			pr_info(" `- type %d ID %#x\n", fd->ops->type, fd->id);
			list_for_each_entry(le, &fd->fd_info_head, desc_list)
				pr_info("   `- FD %d pid %d\n", le->fe->fd, le->pid);
		}
}

/*
 * The gen_id thing is used to optimize the comparison of shared files.
 * If two files have different gen_ids, then they are different for sure.
 * If it matches, we don't know it and have to call sys_kcmp().
 *
 * The kcmp-ids.c engine does this trick, see comments in it for more info.
 */

static u32 make_gen_id(const struct fd_parms *p)
{
	return ((u32)p->stat.st_dev) ^ ((u32)p->stat.st_ino) ^ ((u32)p->pos);
}

int do_dump_gen_file(struct fd_parms *p, int lfd,
		const struct fdtype_ops *ops, struct cr_img *img)
{
	FdinfoEntry e = FDINFO_ENTRY__INIT;
	int ret = -1;

	e.type	= ops->type;
	e.id	= make_gen_id(p);
	e.fd	= p->fd;
	e.flags = p->fd_flags;

	ret = fd_id_generate(p->pid, &e, p);
	if (ret == 1) /* new ID generated */
		ret = ops->dump(lfd, e.id, p);

	if (ret < 0)
		return ret;

	pr_info("fdinfo: type: 0x%2x flags: %#o/%#o pos: 0x%8"PRIx64" fd: %d\n",
		ops->type, p->flags, (int)p->fd_flags, p->pos, p->fd);

	return pb_write_one(img, &e, PB_FDINFO);
}

int fill_fdlink(int lfd, const struct fd_parms *p, struct fd_link *link)
{
	int len;

	link->name[0] = '.';

	len = read_fd_link(lfd, &link->name[1], sizeof(link->name) - 1);
	if (len < 0) {
		pr_err("Can't read link for pid %d fd %d\n", p->pid, p->fd);
		return -1;
	}

	link->len = len + 1;
	return 0;
}

static int fill_fd_params(struct parasite_ctl *ctl, int fd, int lfd,
				struct fd_opts *opts, struct fd_parms *p)
{
	int ret;
	struct statfs fsbuf;
	struct fdinfo_common fdinfo = { .mnt_id = -1, .owner = ctl->pid.virt };

	if (fstat(lfd, &p->stat) < 0) {
		pr_perror("Can't stat fd %d", lfd);
		return -1;
	}

	if (fstatfs(lfd, &fsbuf) < 0) {
		pr_perror("Can't statfs fd %d", lfd);
		return -1;
	}

	if (parse_fdinfo_pid(ctl->pid.real, fd, FD_TYPES__UND, NULL, &fdinfo))
		return -1;

	p->fs_type	= fsbuf.f_type;
	p->ctl		= ctl;
	p->fd		= fd;
	p->pos		= fdinfo.pos;
	p->flags	= fdinfo.flags;
	p->mnt_id	= fdinfo.mnt_id;
	p->pid		= ctl->pid.real;
	p->fd_flags	= opts->flags;

	fown_entry__init(&p->fown);

	pr_info("%d fdinfo %d: pos: 0x%16"PRIx64" flags: %16o/%#x\n",
		ctl->pid.real, fd, p->pos, p->flags, (int)p->fd_flags);

	ret = fcntl(lfd, F_GETSIG, 0);
	if (ret < 0) {
		pr_perror("Can't get owner signum on %d", lfd);
		return -1;
	}
	p->fown.signum = ret;

	if (opts->fown.pid == 0)
		return 0;

	p->fown.pid	 = opts->fown.pid;
	p->fown.pid_type = opts->fown.pid_type;
	p->fown.uid	 = opts->fown.uid;
	p->fown.euid	 = opts->fown.euid;

	return 0;
}

static const struct fdtype_ops *get_misc_dev_ops(int minor)
{
	switch (minor) {
	case TUN_MINOR:
		return &tunfile_dump_ops;
	};

	return NULL;
}

static int dump_chrdev(struct fd_parms *p, int lfd, struct cr_img *img)
{
	int maj = major(p->stat.st_rdev);
	const struct fdtype_ops *ops;

	switch (maj) {
	case MEM_MAJOR:
		ops = &regfile_dump_ops;
		break;
	case MISC_MAJOR:
		ops = get_misc_dev_ops(minor(p->stat.st_rdev));
		if (ops)
			break;
		/* fallthrough */
	default: {
		char more[32];

		if (is_tty(maj, minor(p->stat.st_rdev))) {
			struct fd_link link;

			if (fill_fdlink(lfd, p, &link))
				return -1;
			p->link = &link;
			ops = &tty_dump_ops;
			break;
		}

		sprintf(more, "%d:%d", maj, minor(p->stat.st_rdev));
		return dump_unsupp_fd(p, lfd, img, "chr", more);
	}
	}

	return do_dump_gen_file(p, lfd, ops, img);
}

static int dump_one_file(struct parasite_ctl *ctl, int fd, int lfd, struct fd_opts *opts,
		       struct cr_img *img)
{
	struct fd_parms p = FD_PARMS_INIT;
	const struct fdtype_ops *ops;

	if (fill_fd_params(ctl, fd, lfd, opts, &p) < 0) {
		pr_perror("Can't get stat on %d", fd);
		return -1;
	}

	if (note_file_lock(&ctl->pid, fd, lfd, &p))
		return -1;

	if (S_ISSOCK(p.stat.st_mode))
		return dump_socket(&p, lfd, img);

	if (S_ISCHR(p.stat.st_mode))
		return dump_chrdev(&p, lfd, img);

	if (p.fs_type == ANON_INODE_FS_MAGIC) {
		char link[32];

		if (read_fd_link(lfd, link, sizeof(link)) < 0)
			return -1;

		if (is_eventfd_link(link))
			ops = &eventfd_dump_ops;
		else if (is_eventpoll_link(link))
			ops = &eventpoll_dump_ops;
		else if (is_inotify_link(link))
			ops = &inotify_dump_ops;
		else if (is_fanotify_link(link))
			ops = &fanotify_dump_ops;
		else if (is_signalfd_link(link))
			ops = &signalfd_dump_ops;
		else if (is_timerfd_link(link))
			ops = &timerfd_dump_ops;
		else
			return dump_unsupp_fd(&p, lfd, img, "anon", link);

		return do_dump_gen_file(&p, lfd, ops, img);
	}

	if (S_ISREG(p.stat.st_mode) || S_ISDIR(p.stat.st_mode)) {
		struct fd_link link;

		if (fill_fdlink(lfd, &p, &link))
			return -1;

		p.link = &link;
		if (link.name[1] == '/')
			return do_dump_gen_file(&p, lfd, &regfile_dump_ops, img);

		if (check_ns_proc(&link))
			return do_dump_gen_file(&p, lfd, &nsfile_dump_ops, img);

		return dump_unsupp_fd(&p, lfd, img, "reg", link.name + 1);
	}

	if (S_ISFIFO(p.stat.st_mode)) {
		if (p.fs_type == PIPEFS_MAGIC)
			ops = &pipe_dump_ops;
		else
			ops = &fifo_dump_ops;

		return do_dump_gen_file(&p, lfd, ops, img);
	}

	return dump_unsupp_fd(&p, lfd, img, "unknown", NULL);
}

int dump_task_files_seized(struct parasite_ctl *ctl, struct pstree_item *item,
		struct parasite_drain_fd *dfds)
{
	int *lfds;
	struct cr_img *img;
	struct fd_opts *opts;
	int i, ret = -1;

	pr_info("\n");
	pr_info("Dumping opened files (pid: %d)\n", ctl->pid.real);
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

	img = open_image(CR_FD_FDINFO, O_DUMP, item->ids->files_id);
	if (!img)
		goto err2;

	for (i = 0; i < dfds->nr_fds; i++) {
		ret = dump_one_file(ctl, dfds->fds[i], lfds[i], opts + i, img);
		close(lfds[i]);
		if (ret)
			break;
	}

	close_image(img);

	pr_info("----------------------------------------\n");
err2:
	xfree(opts);
err1:
	xfree(lfds);
err:
	return ret;
}

static int predump_one_fd(int pid, int fd)
{
	const struct fdtype_ops *ops;
	char link[PATH_MAX], t[32];
	int ret = 0;

	snprintf(t, sizeof(t), "/proc/%d/fd/%d", pid, fd);
	ret = readlink(t, link, sizeof(link));
	if (ret < 0) {
		pr_perror("Can't read link of fd %d", fd);
		return -1;
	} else if ((size_t)ret == sizeof(link)) {
		pr_err("Buffer for read link of fd %d is too small\n", fd);
		return -1;
	}
	link[ret] = 0;

	ret = 0;
	if (is_inotify_link(link))
		ops = &inotify_dump_ops;
	else if (is_fanotify_link(link))
		ops = &fanotify_dump_ops;
	else
		goto out;

	pr_debug("Pre-dumping %d's %d fd\n", pid, fd);
	ret = ops->pre_dump(pid, fd);
out:
	return ret;
}

int predump_task_files(int pid)
{
	struct dirent *de;
	DIR *fd_dir;
	int ret = -1;

	pr_info("Pre-dump fds for %d)\n", pid);

	fd_dir = opendir_proc(pid, "fd");
	if (!fd_dir)
		return -1;

	while ((de = readdir(fd_dir))) {
		if (dir_dots(de))
			continue;

		if (predump_one_fd(pid, atoi(de->d_name)))
			goto out;
	}

	ret = 0;
out:
	closedir(fd_dir);
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

static int collect_fd(int pid, FdinfoEntry *e, struct rst_info *rst_info)
{
	struct fdinfo_list_entry *le, *new_le;
	struct file_desc *fdesc;

	pr_info("Collect fdinfo pid=%d fd=%d id=%#x\n",
		pid, e->fd, e->id);

	new_le = shmalloc(sizeof(*new_le));
	if (!new_le)
		return -1;

	futex_init(&new_le->real_pid);
	new_le->pid = pid;
	new_le->fe = e;

	fdesc = find_file_desc(e);
	if (fdesc == NULL) {
		pr_err("No file for fd %d id %#x\n", e->fd, e->id);
		return -1;
	}

	list_for_each_entry(le, &fdesc->fd_info_head, desc_list)
		if (pid_rst_prio(new_le->pid, le->pid))
			break;

	if (fdesc->ops->collect_fd)
		fdesc->ops->collect_fd(fdesc, new_le, rst_info);
	else
		collect_gen_fd(new_le, rst_info);

	list_add_tail(&new_le->desc_list, &le->desc_list);
	new_le->desc = fdesc;

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
	e->fd		= reserve_service_fd(CTL_TTY_OFF);
	e->type		= FD_TYPES__TTY;

	if (collect_fd(pid, e, rst_info)) {
		xfree(e);
		return -1;
	}

	return 0;
}

int prepare_fd_pid(struct pstree_item *item)
{
	int ret = 0;
	struct cr_img *img;
	pid_t pid = item->pid.virt;
	struct rst_info *rst_info = rsti(item);

	INIT_LIST_HEAD(&rst_info->fds);
	INIT_LIST_HEAD(&rst_info->eventpoll);
	INIT_LIST_HEAD(&rst_info->tty_slaves);
	INIT_LIST_HEAD(&rst_info->tty_ctty);

	if (!fdinfo_per_id) {
		img = open_image(CR_FD_FDINFO, O_RSTR, pid);
		if (!img)
			return -1;
	} else {
		if (item->ids == NULL) /* zombie */
			return 0;

		if (rsti(item)->fdt && rsti(item)->fdt->pid != item->pid.virt)
			return 0;

		img = open_image(CR_FD_FDINFO, O_RSTR, item->ids->files_id);
		if (!img)
			return -1;
	}

	while (1) {
		FdinfoEntry *e;

		ret = pb_read_one_eof(img, &e, PB_FDINFO);
		if (ret <= 0)
			break;

		ret = collect_fd(pid, e, rst_info);
		if (ret < 0) {
			fdinfo_entry__free_unpacked(e, NULL);
			break;
		}
	}

	close_image(img);
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

struct fd_open_state {
	char *name;
	int (*cb)(int, struct fdinfo_list_entry *);

	/*
	 * Two last stages -- receive fds and post-open them -- are
	 * not required always. E.g. if no fd sharing takes place
	 * or task doens't have any files that need to be post-opened.
	 *
	 * Thus, in order not to scan through fdinfo-s lists in vain
	 * and speed things up a little bit, we may want to skeep these.
	 */
	bool required;
};

static int open_transport_fd(int pid, struct fdinfo_list_entry *fle);
static int open_fd(int pid, struct fdinfo_list_entry *fle);
static int receive_fd(int pid, struct fdinfo_list_entry *fle);
static int post_open_fd(int pid, struct fdinfo_list_entry *fle);

static struct fd_open_state states[] = {
	{ "prepare",		open_transport_fd,	true,},
	{ "create",		open_fd,		true,},
	{ "receive",		receive_fd,		false,},
	{ "post_create",	post_open_fd,		false,},
};

#define want_recv_stage()	do { states[2].required = true; } while (0)
#define want_post_open_stage()	do { states[3].required = true; } while (0)

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
		goto err;
	}

	ret = reopen_fd_as(fle->fe->fd, sock);
	if (ret < 0)
		goto err;

	pr_info("\t\tWake up fdinfo pid=%d fd=%d\n", fle->pid, fle->fe->fd);
	futex_set_and_wake(&fle->real_pid, getpid());
	want_recv_stage();

	return 0;
err:
	close(sock);
	return -1;
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

	/* make sure we won't clash with an inherit fd */
	if (inherit_fd_resolve_clash(dfd) < 0)
		return -1;

	pr_info("\t\t\tGoing to dup %d into %d\n", fd, dfd);
	if (move_img_fd(sock, dfd))
		return -1;

	if (dup2(fd, dfd) != dfd) {
		pr_perror("Can't dup local fd %d -> %d", fd, dfd);
		return -1;
	}

	if (fcntl(dfd, F_SETFD, fle->fe->flags) == -1) {
		pr_perror("Unable to set file descriptor flags");
		return -1;
	}

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
			goto out;
		}
	}

	ret = 0;
out:
	close(sock);
	return ret;
}

static int open_fd(int pid, struct fdinfo_list_entry *fle)
{
	struct file_desc *d = fle->desc;
	int new_fd;

	if (d->ops->post_open)
		want_post_open_stage();

	if (fle != file_master(d))
		return 0;

	new_fd = d->ops->open(d);
	if (new_fd < 0)
		return -1;

	if (reopen_fd_as(fle->fe->fd, new_fd))
		return -1;

	if (fcntl(fle->fe->fd, F_SETFD, fle->fe->flags) == -1) {
		pr_perror("Unable to set file descriptor flags");
		return -1;
	}

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

	if (fcntl(fle->fe->fd, F_SETFD, fle->fe->flags) == -1) {
		pr_perror("Unable to set file descriptor flags");
		return -1;
	}

	return 0;
}

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

static struct inherit_fd *inherit_fd_lookup_fd(int fd, const char *caller);

int close_old_fds(struct pstree_item *me)
{
	DIR *dir;
	struct dirent *de;
	int fd, ret;

	dir = opendir_proc(PROC_SELF, "fd");
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

		if ((!is_any_service_fd(fd)) && (dirfd(dir) != fd) &&
		    !inherit_fd_lookup_fd(fd, __FUNCTION__))
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

	/*
	 * This must be done after forking to allow child
	 * to get the cgroup fd so it can move into the
	 * correct /tasks file if it is in a different cgroup
	 * set than its parent
	 */
	close_service_fd(CGROUP_YARD);
	close_pid_proc(); /* flush any proc cached fds we may have */

	if (rsti(me)->fdt) {
		struct fdt *fdt = rsti(me)->fdt;

		/*
		 * Wait all tasks, who share a current fd table.
		 * We should be sure, that nobody use any file
		 * descriptor while fdtable is being restored.
		 */
		futex_inc_and_wake(&fdt->fdt_lock);
		futex_wait_while_lt(&fdt->fdt_lock, fdt->nr);

		if (fdt->pid != me->pid.virt) {
			pr_info("File descriptor table is shared with %d\n", fdt->pid);
			futex_wait_until(&fdt->fdt_lock, fdt->nr + 1);
			goto out;
		}
	}

	for (state = 0; state < ARRAY_SIZE(states); state++) {
		if (!states[state].required) {
			pr_debug("Skipping %s fd stage\n", states[state].name);
			continue;
		}

		ret = open_fdinfos(me->pid.virt, &rsti(me)->fds, state);
		if (ret)
			break;

		/*
		 * Now handle TTYs. Slaves are delayed to be sure masters
		 * are already opened.
		 */
		ret = open_fdinfos(me->pid.virt, &rsti(me)->tty_slaves, state);
		if (ret)
			break;

		/*
		 * The eventpoll descriptors require all the other ones
		 * to be already restored, thus we store them in a separate
		 * list and restore at the very end.
		 */
		ret = open_fdinfos(me->pid.virt, &rsti(me)->eventpoll, state);
		if (ret)
			break;
	}

	if (ret)
		goto out_w;

	for (state = 0; state < ARRAY_SIZE(states); state++) {
		if (!states[state].required) {
			pr_debug("Skipping %s fd stage\n", states[state].name);
			continue;
		}

		/*
		 * Opening current TTYs require session to be already set up,
		 * thus slave peers already handled now it's time for cttys,
		 */
		ret = open_fdinfos(me->pid.virt, &rsti(me)->tty_ctty, state);
		if (ret)
			break;
	}
out_w:
	if (rsti(me)->fdt)
		futex_inc_and_wake(&rsti(me)->fdt->fdt_lock);
out:
	close_service_fd(CR_PROC_FD_OFF);
	tty_fini_fds();
	return ret;
}

static int fchroot(int fd)
{
	char fd_path[PSFDS];
	int proc;

	/*
	 * There's no such thing in syscalls. We can emulate
	 * it using the /proc/self/fd/ :)
	 *
	 * But since there might be no /proc mount in our mount
	 * namespace, we will have to ... workaround it.
	 */

	proc = get_service_fd(PROC_FD_OFF);
	if (fchdir(proc) < 0) {
		pr_perror("Can't chdir to proc");
		return -1;
	}

	sprintf(fd_path, "./self/fd/%d", fd);
	pr_debug("Going to chroot into %s\n", fd_path);
	return chroot(fd_path);
}

int restore_fs(struct pstree_item *me)
{
	int dd_root = -1, dd_cwd = -1, ret, err = -1;
	struct rst_info *ri = rsti(me);

	/*
	 * First -- open both descriptors. We will not
	 * be able to open the cwd one after we chroot.
	 */

	dd_root = open_reg_fd(ri->root);
	if (dd_root < 0) {
		pr_err("Can't open root\n");
		goto out;
	}

	dd_cwd = open_reg_fd(ri->cwd);
	if (dd_cwd < 0) {
		pr_err("Can't open cwd\n");
		goto out;
	}

	/*
	 * Now do chroot/chdir. Chroot goes first as it
	 * calls chdir into proc service descriptor so
	 * we'd need to fix chdir after it anyway.
	 */

	ret = fchroot(dd_root);
	if (ret < 0) {
		pr_perror("Can't change root");
		goto out;
	}

	ret = fchdir(dd_cwd);
	if (ret < 0) {
		pr_perror("Can't change cwd");
		goto out;
	}

	if (ri->has_umask) {
		pr_info("Restoring umask to %o\n", ri->umask);
		umask(ri->umask);
	}

	err = 0;
out:
	if (dd_cwd >= 0)
		close(dd_cwd);
	if (dd_root >= 0)
		close(dd_root);

	return err;
}

int prepare_fs_pid(struct pstree_item *item)
{
	pid_t pid = item->pid.virt;
	struct rst_info *ri = rsti(item);
	struct cr_img *img;
	FsEntry *fe;
	int ret = -1;

	img = open_image(CR_FD_FS, O_RSTR, pid);
	if (!img)
		goto out;

	ret = pb_read_one_eof(img, &fe, PB_FS);
	close_image(img);
	if (ret <= 0)
		goto out;

	ri->cwd = collect_special_file(fe->cwd_id);
	if (!ri->cwd) {
		pr_err("Can't find task cwd file\n");
		goto out_f;
	}

	ri->root = collect_special_file(fe->root_id);
	if (!ri->root) {
		pr_err("Can't find task root file\n");
		goto out_f;
	}

	ri->has_umask = fe->has_umask;
	ri->umask = fe->umask;

	ret = 0;
out_f:
	fs_entry__free_unpacked(fe, NULL);
out:
	return ret;
}

int shared_fdt_prepare(struct pstree_item *item)
{
	struct pstree_item *parent = item->parent;
	struct fdt *fdt;

	if (!rsti(parent)->fdt) {
		fdt = shmalloc(sizeof(*rsti(item)->fdt));
		if (fdt == NULL)
			return -1;

		rsti(parent)->fdt = fdt;

		futex_init(&fdt->fdt_lock);
		fdt->nr = 1;
		fdt->pid = parent->pid.virt;
	} else
		fdt = rsti(parent)->fdt;

	rsti(item)->fdt = fdt;
	rsti(item)->service_fd_id = fdt->nr;
	fdt->nr++;
	if (pid_rst_prio(item->pid.virt, fdt->pid))
		fdt->pid = item->pid.virt;

	return 0;
}

/*
 * Inherit fd support.
 *
 * There are cases where a process's file descriptor cannot be restored
 * from the checkpointed image.  For example, a pipe file descriptor with
 * one end in the checkpointed process and the other end in a separate
 * process (that was not part of the checkpointed process tree) cannot be
 * restored because after checkpoint the pipe would be broken and removed.
 *
 * There are also cases where the user wants to use a new file during
 * restore instead of the original file in the checkpointed image.  For
 * example, the user wants to change the log file of a process from
 * /path/to/oldlog to /path/to/newlog.
 *
 * In these cases, criu's caller should set up a new file descriptor to be
 * inherited by the restored process and specify it with the --inherit-fd
 * command line option.  The argument of --inherit-fd has the format
 * fd[%d]:%s, where %d tells criu which of its own file descriptor to use
 * for restoring file identified by %s.
 *
 * As a debugging aid, if the argument has the format debug[%d]:%s, it tells
 * criu to write out the string after colon to the file descriptor %d.  This
 * can be used to leave a "restore marker" in the output stream of the process.
 *
 * It's important to note that inherit fd support breaks applications
 * that depend on the state of the file descriptor being inherited.  So,
 * consider inherit fd only for specific use cases that you know for sure
 * won't break the application.
 *
 * For examples please visit http://criu.org/Category:HOWTO.
 */

struct inherit_fd {
	struct list_head inh_list;
	char *inh_id;		/* file identifier */
	int inh_fd;		/* criu's descriptor to inherit */
	dev_t inh_dev;
	ino_t inh_ino;
	mode_t inh_mode;
	dev_t inh_rdev;
};

/*
 * Return 1 if inherit fd has been closed or reused, 0 otherwise.
 *
 * Some parts of the file restore engine can close an inherit fd
 * explicitly by close() or implicitly by dup2() to reuse that descriptor.
 * In some specific functions (for example, send_fd_to_self()), we
 * check for clashes at the beginning of the function and, therefore,
 * these specific functions will not reuse an inherit fd.  However, to
 * avoid adding a ton of clash detect and resolve code everywhere we close()
 * and/or dup2(), we just make sure that when we're dup()ing or close()ing
 * our inherit fd we're still dealing with the same fd that we inherited.
 */
static int inherit_fd_reused(struct inherit_fd *inh)
{
	struct stat sbuf;

	if (fstat(inh->inh_fd, &sbuf) == -1) {
		if (errno == EBADF) {
			pr_debug("Inherit fd %s -> %d has been closed\n",
				inh->inh_id, inh->inh_fd);
			return 1;
		}
		pr_perror("Can't fstat inherit fd %d", inh->inh_fd);
		return -1;
	}

	if (inh->inh_dev != sbuf.st_dev || inh->inh_ino != sbuf.st_ino ||
	    inh->inh_mode != sbuf.st_mode || inh->inh_rdev != sbuf.st_rdev) {
		pr_info("Inherit fd %s -> %d has been reused\n",
			inh->inh_id, inh->inh_fd);
		return 1;
	}
	return 0;
}

/*
 * We can't print diagnostics messages in this function because the
 * log file isn't initialized yet.
 */
int inherit_fd_parse(char *optarg)
{
	char *cp = NULL;
	int n = -1;
	int fd = -1;
	int dbg = 0;

	/*
	 * Parse the argument.
	 */
	if (!strncmp(optarg, "fd", 2))
		cp = &optarg[2];
	else if (!strncmp(optarg, "debug", 5)) {
		cp = &optarg[5];
		dbg = 1;
	}
	if (cp) {
		n = sscanf(cp, "[%d]:", &fd);
		cp = strchr(optarg, ':');
	}
	if (n != 1 || fd < 0 || !cp || !cp[1]) {
		pr_err("Invalid inherit fd argument: %s\n", optarg);
		return -1;
	}

	/*
	 * If the argument is a debug string, write it to fd.
	 * Otherwise, add it to the inherit fd list.
	 */
	cp++;
	if (dbg) {
		n = strlen(cp);
		if (write(fd, cp, n) != n) {
			pr_err("Can't write debug message %s to inherit fd %d\n",
				cp, fd);
			return -1;
		}
		return 0;
	}

	return inherit_fd_add(fd, cp);
}

int inherit_fd_add(int fd, char *key)
{
	struct inherit_fd *inh;
	struct stat sbuf;

	if (fstat(fd, &sbuf) == -1) {
		pr_perror("Can't fstat inherit fd %d", fd);
		return -1;
	}

	inh = xmalloc(sizeof *inh);
	if (inh == NULL)
		return -1;

	inh->inh_id = key;
	inh->inh_fd = fd;
	inh->inh_dev = sbuf.st_dev;
	inh->inh_ino = sbuf.st_ino;
	inh->inh_mode = sbuf.st_mode;
	inh->inh_rdev = sbuf.st_rdev;
	list_add_tail(&inh->inh_list, &opts.inherit_fds);
	return 0;
}

/*
 * Log the inherit fd list.  Called for diagnostics purposes
 * after the log file is initialized.
 */
void inherit_fd_log(void)
{
	struct inherit_fd *inh;

	list_for_each_entry(inh, &opts.inherit_fds, inh_list) {
		pr_info("File %s will be restored from inherit fd %d\n",
			inh->inh_id, inh->inh_fd);
	}
}

/*
 * Look up the inherit fd list by a file identifier.
 */
static int inherit_fd_lookup_id(char *id)
{
	int ret;
	struct inherit_fd *inh;

	ret = -1;
	list_for_each_entry(inh, &opts.inherit_fds, inh_list) {
		if (!strcmp(inh->inh_id, id)) {
			if (!inherit_fd_reused(inh)) {
				ret = inh->inh_fd;
				pr_debug("Found id %s (fd %d) in inherit fd list\n",
					id, ret);
			}
			break;
		}
	}
	return ret;
}

bool inherited_fd(struct file_desc *d, int *fd_p)
{
	char buf[32], *id_str;
	int i_fd;

	if (!d->ops->name)
		return false;

	id_str = d->ops->name(d, buf, sizeof(buf));
	i_fd = inherit_fd_lookup_id(id_str);
	if (i_fd < 0)
		return false;

	*fd_p = dup(i_fd);
	if (*fd_p < 0)
		pr_perror("Inherit fd DUP failed");
	else
		pr_info("File %s will be restored from fd %d duped "
				"from inherit fd %d\n", id_str, *fd_p, i_fd);
	return true;
}

/*
 * Look up the inherit fd list by a file descriptor.
 */
static struct inherit_fd *inherit_fd_lookup_fd(int fd, const char *caller)
{
	struct inherit_fd *ret;
	struct inherit_fd *inh;

	ret = NULL;
	list_for_each_entry(inh, &opts.inherit_fds, inh_list) {
		if (inh->inh_fd == fd) {
			if (!inherit_fd_reused(inh)) {
				ret = inh;
				pr_debug("Found fd %d (id %s) in inherit fd list (caller %s)\n",
					fd, inh->inh_id, caller);
			}
			break;
		}
	}
	return ret;
}

/*
 * If the specified fd clashes with an inherit fd,
 * move the inherit fd.
 */
int inherit_fd_resolve_clash(int fd)
{
	int newfd;
	struct inherit_fd *inh;

	inh = inherit_fd_lookup_fd(fd, __FUNCTION__);
	if (inh == NULL)
		return 0;

	newfd = dup(fd);
	if (newfd == -1) {
		pr_perror("Can't dup inherit fd %d", fd);
		return -1;
	}

	if (close(fd) == -1) {
		pr_perror("Can't close inherit fd %d", fd);
		return -1;
	}

	inh->inh_fd = newfd;
	pr_debug("Inherit fd %d moved to %d to resolve clash\n", fd, inh->inh_fd);
	return 0;
}

/*
 * Close all inherit fds.
 */
int inherit_fd_fini()
{
	int reused;
	struct inherit_fd *inh;

	list_for_each_entry(inh, &opts.inherit_fds, inh_list) {
		if (inh->inh_fd < 0) {
			pr_err("File %s in inherit fd list has invalid fd %d\n",
				inh->inh_id, inh->inh_fd);
			return -1;
		}

		reused = inherit_fd_reused(inh);
		if (reused < 0)
			return -1;

		if (!reused) {
			pr_debug("Closing inherit fd %d -> %s\n", inh->inh_fd,
				inh->inh_id);
			if (close_safe(&inh->inh_fd) < 0)
				return -1;
		}
	}
	return 0;
}
