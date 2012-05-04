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

#include "crtools.h"

#include "files.h"
#include "image.h"
#include "list.h"
#include "util.h"
#include "util-net.h"
#include "lock.h"
#include "sockets.h"

static struct fdinfo_list_entry *fdinfo_list;
static int nr_fdinfo_list;

#define FDESC_HASH_SIZE	64
static struct list_head file_descs[FDESC_HASH_SIZE];

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
		INIT_LIST_HEAD(&file_descs[i]);

	return 0;
}

void file_desc_add(struct file_desc *d, u32 id,
		struct file_desc_ops *ops)
{
	d->id = id;
	d->ops = ops;
	INIT_LIST_HEAD(&d->fd_info_head);

	list_add_tail(&d->hash, &file_descs[id % FDESC_HASH_SIZE]);
}

struct file_desc *find_file_desc_raw(int type, u32 id)
{
	struct file_desc *d;
	struct list_head *chain;

	chain = &file_descs[id % FDESC_HASH_SIZE];
	list_for_each_entry(d, chain, hash)
		if (d->ops->type == type && d->id == id)
			return d;

	return NULL;
}

static inline struct file_desc *find_file_desc(struct fdinfo_entry *fe)
{
	return find_file_desc_raw(fe->type, fe->id);
}

struct fdinfo_list_entry *file_master(struct file_desc *d)
{
	BUG_ON(list_empty(&d->fd_info_head));
	return list_first_entry(&d->fd_info_head,
			struct fdinfo_list_entry, desc_list);
}

struct reg_file_info {
	struct reg_file_entry rfe;
	char *remap_path;
	char *path;
	struct file_desc d;
};

void show_saved_files(void)
{
	int i;
	struct file_desc *fd;

	pr_info("File descs:\n");
	for (i = 0; i < FDESC_HASH_SIZE; i++)
		list_for_each_entry(fd, &file_descs[i], hash) {
			struct fdinfo_list_entry *le;

			pr_info(" `- type %d ID %#x\n", fd->ops->type, fd->id);
			list_for_each_entry(le, &fd->fd_info_head, desc_list)
				pr_info("   `- FD %d pid %d\n", le->fe.fd, le->pid);
		}
}

int restore_fown(int fd, fown_t *fown)
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

int rst_file_params(int fd, fown_t *fown, int flags)
{
	if (set_fd_flags(fd, flags) < 0)
		return -1;
	if (restore_fown(fd, fown) < 0)
		return -1;
	return 0;
}

static int open_fe_fd(struct file_desc *d);

static struct file_desc_ops reg_desc_ops = {
	.type = FDINFO_REG,
	.open = open_fe_fd,
};

struct ghost_file {
	u32 id;
	char *path;
	struct list_head list;
};

static LIST_HEAD(ghost_files);

void clear_ghost_files(void)
{
	struct ghost_file *gf;

	pr_info("Unlinking ghosts\n");

	list_for_each_entry(gf, &ghost_files, list) {
		pr_info("\t`- %s\n", gf->path);
		unlink(gf->path);
	}
}

static int open_remap_ghost(struct reg_file_info *rfi,
		struct remap_file_path_entry *rfe)
{
	struct ghost_file *gf;
	struct ghost_file_entry gfe;
	int gfd, ifd;

	list_for_each_entry(gf, &ghost_files, list)
		if (gf->id == rfe->remap_id)
			goto gf_found;

	/*
	 * Ghost not found. We will create one in the same dir
	 * as the very first client of it thus resolving any
	 * issues with cross-device links.
	 */

	pr_info("Opening ghost file %#x for %s\n", rfe->remap_id, rfi->path);

	gf = xmalloc(sizeof(*gf));
	if (!gf)
		return -1;
	gf->path = xmalloc(PATH_MAX);
	if (!gf->path)
		return -1;

	ifd = open_image_ro(CR_FD_GHOST_FILE, rfe->remap_id);
	if (ifd < 0)
		return -1;

	if (read_img(ifd, &gfe) < 0)
		return -1;

	sprintf(gf->path, "%s.cr.%x.ghost", rfi->path, rfe->remap_id);
	gfd = open(gf->path, O_WRONLY | O_CREAT | O_EXCL, gfe.mode);
	if (gfd < 0) {
		pr_perror("Can't open ghost file");
		return -1;
	}

	if (fchown(gfd, gfe.uid, gfe.gid) < 0) {
		pr_perror("Can't reset user/group on ghost %#x\n", rfe->remap_id);
		return -1;
	}

	if (copy_file(ifd, gfd, 0) < 0)
		return -1;

	close(ifd);
	close(gfd);

	gf->id = rfe->remap_id;
	list_add_tail(&gf->list, &ghost_files);
gf_found:
	rfi->remap_path = gf->path;
	return 0;
}

static int collect_remaps(void)
{
	int fd, ret = 0;

	fd = open_image_ro(CR_FD_REMAP_FPATH);
	if (fd < 0)
		return -1;

	while (1) {
		struct remap_file_path_entry rfe;
		struct file_desc *fdesc;
		struct reg_file_info *rfi;

		ret = read_img_eof(fd, &rfe);
		if (ret <= 0)
			break;

		ret = -1;

		if (!(rfe.remap_id & REMAP_GHOST)) {
			pr_err("Non ghost remap not supported @%#x\n",
					rfe.orig_id);
			break;
		}

		fdesc = find_file_desc_raw(FDINFO_REG, rfe.orig_id);
		if (fdesc == NULL) {
			pr_err("Remap for non existing file %#x\n",
					rfe.orig_id);
			break;
		}

		rfe.remap_id &= ~REMAP_GHOST;
		rfi = container_of(fdesc, struct reg_file_info, d);
		pr_info("Configuring remap %#x -> %#x\n", rfi->rfe.id, rfe.remap_id);
		ret = open_remap_ghost(rfi, &rfe);
		if (ret < 0)
			break;
	}

	close(fd);
	return ret;
}

int collect_reg_files(void)
{
	struct reg_file_info *rfi = NULL;
	int fd, ret = -1;

	fd = open_image_ro(CR_FD_REG_FILES);
	if (fd < 0)
		return -1;

	while (1) {
		int len;

		rfi = xmalloc(sizeof(*rfi));
		ret = -1;
		if (rfi == NULL)
			break;

		rfi->path = NULL;
		ret = read_img_eof(fd, &rfi->rfe);
		if (ret <= 0)
			break;

		len = rfi->rfe.len;
		rfi->path = xmalloc(len + 1);
		ret = -1;
		if (rfi->path == NULL)
			break;

		ret = read_img_buf(fd, rfi->path, len);
		if (ret < 0)
			break;

		rfi->remap_path = NULL;
		rfi->path[len] = '\0';

		pr_info("Collected [%s] ID %#x\n", rfi->path, rfi->rfe.id);
		file_desc_add(&rfi->d, rfi->rfe.id, &reg_desc_ops);
	}

	if (rfi) {
		xfree(rfi->path);
		xfree(rfi);
	}

	close(fd);

	return collect_remaps();
}

static int collect_fd(int pid, struct fdinfo_entry *e, struct rst_info *rst_info)
{
	int i;
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
	le->fe = *e;

	fdesc = find_file_desc(e);
	if (fdesc == NULL) {
		pr_err("No file for fd %d id %d\n", e->fd, e->id);
		return -1;
	}

	list_for_each_entry(l, &fdesc->fd_info_head, desc_list)
		if (l->pid > le->pid)
			break;

	list_add_tail(&le->desc_list, &l->desc_list);

	if (unlikely(le->fe.type == FDINFO_EVENTPOLL))
		list_add_tail(&le->ps_list, &rst_info->eventpoll);
	else
		list_add_tail(&le->ps_list, &rst_info->fds);
	return 0;
}

int prepare_fd_pid(int pid, struct rst_info *rst_info)
{
	int fdinfo_fd, ret = 0;
	u32 type = 0;

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
		struct fdinfo_entry e;

		ret = read_img_eof(fdinfo_fd, &e);
		if (ret <= 0)
			break;

		ret = collect_fd(pid, &e, rst_info);
		if (ret < 0)
			break;
	}

	close(fdinfo_fd);
	return ret;
}

static int open_fe_fd(struct file_desc *d)
{
	struct reg_file_info *rfi;
	int tmp;

	rfi = container_of(d, struct reg_file_info, d);

	if (rfi->remap_path)
		if (link(rfi->remap_path, rfi->path) < 0) {
			pr_perror("Can't link %s -> %s\n",
					rfi->remap_path, rfi->path);
			return -1;
		}

	tmp = open(rfi->path, rfi->rfe.flags);
	if (tmp < 0) {
		pr_perror("Can't open file %s", rfi->path);
		return -1;
	}

	if (rfi->remap_path)
		unlink(rfi->path);

	lseek(tmp, rfi->rfe.pos, SEEK_SET);

	if (restore_fown(tmp, &rfi->rfe.fown))
		return -1;

	return tmp;
}
int open_reg_by_id(u32 id)
{
	struct file_desc *fd;

	fd = find_file_desc_raw(FDINFO_REG, id);
	if (fd == NULL) {
		pr_perror("Can't find regfile for %#x\n", id);
		return -1;
	}

	return open_fe_fd(fd);
}

#define SETFL_MASK (O_APPEND | O_NONBLOCK | O_NDELAY | O_DIRECT | O_NOATIME)
int set_fd_flags(int fd, int flags)
{
	int old;

	old = fcntl(fd, F_GETFL, 0);
	if (old < 0)
		return old;

	flags = (SETFL_MASK & flags) | (old & ~SETFL_MASK);

	return fcntl(fd, F_SETFL, flags);
}

static void transport_name_gen(struct sockaddr_un *addr, int *len,
		int pid, int fd)
{
	addr->sun_family = AF_UNIX;
	snprintf(addr->sun_path, UNIX_PATH_MAX, "x/crtools-fd-%d-%d", pid, fd);
	*len = SUN_LEN(addr);
	*addr->sun_path = '\0';
}

static int should_open_transport(struct fdinfo_entry *fe, struct file_desc *fd)
{
	if (fd->ops->want_transport)
		return fd->ops->want_transport(fe, fd);
	else
		return 0;
}

static int open_transport_fd(int pid, struct fdinfo_entry *fe, struct file_desc *d)
{
	struct fdinfo_list_entry *fle;
	struct sockaddr_un saddr;
	int sock;
	int ret, sun_len;

	fle = file_master(d);

	if (fle->pid == pid) {
		if (fle->fe.fd == fe->fd) {
			/* file master */
			if (!should_open_transport(fe, d))
				return 0;
		} else
			return 0;
	}

	transport_name_gen(&saddr, &sun_len, getpid(), fe->fd);

	pr_info("\t\tCreate transport fd %s\n", saddr.sun_path + 1);

	list_for_each_entry(fle, &d->fd_info_head, desc_list)
		if ((fle->pid == pid) && (fle->fe.fd == fe->fd))
			break;

	BUG_ON(&d->fd_info_head == &fle->desc_list);

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

	ret = reopen_fd_as(fe->fd, sock);
	if (ret < 0)
		return -1;

	pr_info("\t\tWake up fdinfo pid=%d fd=%d\n", fle->pid, fle->fe.fd);
	futex_set_and_wake(&fle->real_pid, getpid());

	return 0;
}

int send_fd_to_peer(int fd, struct fdinfo_list_entry *fle, int tsk)
{
	struct sockaddr_un saddr;
	int len;

	pr_info("\t\tWait fdinfo pid=%d fd=%d\n", fle->pid, fle->fe.fd);
	futex_wait_while(&fle->real_pid, 0);
	transport_name_gen(&saddr, &len,
			futex_get(&fle->real_pid), fle->fe.fd);
	pr_info("\t\tSend fd %d to %s\n", fd, saddr.sun_path + 1);
	return send_fd(tsk, &saddr, len, fd);
}

static int open_fd(int pid, struct fdinfo_entry *fe, struct file_desc *d)
{
	int tmp;
	int serv, sock;
	struct fdinfo_list_entry *fle;

	fle = file_master(d);
	if ((fle->pid != pid) || (fe->fd != fle->fe.fd))
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
			pr_info("\t\t\tGoing to dup %d into %d\n", fe->fd, fle->fe.fd);
			if (fe->fd == fle->fe.fd)
				continue;

			if (move_img_fd(&sock, fle->fe.fd))
				return -1;

			if (dup2(fe->fd, fle->fe.fd) != fle->fe.fd) {
				pr_perror("Can't dup local fd %d -> %d",
						fe->fd, fle->fe.fd);
				return -1;
			}

			fcntl(fle->fe.fd, F_SETFD, fle->fe.flags);

			continue;
		}

		if (send_fd_to_peer(fe->fd, fle, sock)) {
			pr_perror("Can't send file descriptor");
			return -1;
		}
	}

	close(sock);
out:
	return 0;
}

static int receive_fd(int pid, struct fdinfo_entry *fe, struct file_desc *d)
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

static int open_fdinfo(int pid, struct fdinfo_entry *fe, int state)
{
	u32 mag;
	int ret = 0;
	struct file_desc *fdesc;

	fdesc = find_file_desc(fe);
	pr_info("\tRestoring fd %d (state -> %d)\n", fe->fd, state);

	switch (state) {
	case FD_STATE_PREP:
		ret = open_transport_fd(pid, fe, fdesc);
		break;
	case FD_STATE_CREATE:
		ret = open_fd(pid, fe, fdesc);
		break;
	case FD_STATE_RECV:
		ret = receive_fd(pid, fe, fdesc);
		break;
	}

	return ret;
}

int prepare_fds(struct pstree_item *me)
{
	u32 type = 0, ret;
	int state;
	struct fdinfo_list_entry *fle;
	int nr = 0;

	pr_info("Opening fdinfo-s\n");

	for (state = 0; state < FD_STATE_MAX; state++) {
		list_for_each_entry(fle, &me->rst->fds, ps_list) {
			ret = open_fdinfo(me->pid, &fle->fe, state);
			if (ret)
				goto done;
		}

		/*
		 * The eventpoll descriptors require all the other ones
		 * to be already restored, thus we store them in a separate
		 * list and restore at the very end.
		 */
		list_for_each_entry(fle, &me->rst->eventpoll, ps_list) {
			ret = open_fdinfo(me->pid, &fle->fe, state);
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
	int ifd, cwd;
	struct fs_entry fe;

	ifd = open_image_ro(CR_FD_FS, pid);
	if (ifd < 0)
		return -1;

	if (read_img(ifd, &fe) < 0)
		return -1;

	cwd = open_reg_by_id(fe.cwd_id);
	if (cwd < 0)
		return -1;

	if (fchdir(cwd) < 0) {
		pr_perror("Can't change root");
		return -1;
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

	return 0;
}

int get_filemap_fd(int pid, struct vma_entry *vma_entry)
{
	return open_reg_by_id(vma_entry->shmid);
}
