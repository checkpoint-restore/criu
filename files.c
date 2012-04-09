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

int prepare_shared_fdinfo(void)
{
	int i;

	fdinfo_list = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANON, 0, 0);
	if (fdinfo_list == MAP_FAILED) {
		pr_perror("Can't map fdinfo_list");
		return -1;
	}

	for (i = 0; i < FDESC_HASH_SIZE; i++)
		INIT_LIST_HEAD(&file_descs[i]);

	return 0;
}

void file_desc_add(struct file_desc *d, int type, u32 id,
		struct file_desc_ops *ops)
{
	d->type = type;
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
		if (d->type == type && d->id == id)
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
			struct fdinfo_list_entry, list);
}

struct reg_file_info {
	struct reg_file_entry rfe;
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

			pr_info(" `- type %d ID %x\n", fd->type, fd->id);
			list_for_each_entry(le, &fd->fd_info_head, list)
				pr_info("   `- FD %d pid %d\n", le->fd, le->pid);
		}
}

static struct reg_file_info *find_reg_file(int id)
{
	struct file_desc *fd;

	fd = find_file_desc_raw(FDINFO_REG, id);
	return container_of(fd, struct reg_file_info, d);
}

static int open_fe_fd(struct file_desc *d);

static struct file_desc_ops reg_desc_ops = {
	.open = open_fe_fd,
};

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

		rfi->path[len] = '\0';

		pr_info("Collected [%s] ID %x\n", rfi->path, rfi->rfe.id);
		file_desc_add(&rfi->d, FDINFO_REG, rfi->rfe.id,
				&reg_desc_ops);
	}

	if (rfi) {
		xfree(rfi->path);
		xfree(rfi);
	}

	close(fd);
	return ret;
}

static int collect_fd(int pid, struct fdinfo_entry *e)
{
	int i;
	struct fdinfo_list_entry *l, *le = &fdinfo_list[nr_fdinfo_list];
	struct file_desc *fdesc;

	pr_info("Collect fdinfo pid=%d fd=%ld id=%16x\n",
		pid, e->addr, e->id);

	nr_fdinfo_list++;
	if ((nr_fdinfo_list) * sizeof(struct fdinfo_list_entry) >= 4096) {
		pr_err("OOM storing fdinfo_list_entries\n");
		return -1;
	}

	le->pid = pid;
	le->fd = e->addr;
	futex_init(&le->real_pid);

	fdesc = find_file_desc(e);
	if (fdesc == NULL) {
		pr_err("No file for fd %d id %d\n", (int)e->addr, e->id);
		return -1;
	}

	list_for_each_entry(l, &fdesc->fd_info_head, list)
		if (l->pid > le->pid)
			break;

	list_add_tail(&le->list, &l->list);
	return 0;
}

int prepare_fd_pid(int pid)
{
	int fdinfo_fd, ret = 0;
	u32 type = 0;

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

		if (fd_is_special(&e))
			continue;

		ret = collect_fd(pid, &e);
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

	tmp = open(rfi->path, rfi->rfe.flags);
	if (tmp < 0) {
		pr_perror("Can't open file %s", rfi->path);
		return -1;
	}

	lseek(tmp, rfi->rfe.pos, SEEK_SET);

	return tmp;
}
static int find_open_fe_fd(struct fdinfo_entry *fe)
{
	struct reg_file_info *rfi;
	int tmp;

	rfi = find_reg_file(fe->id);
	if (!rfi) {
		pr_err("Can't find file id %x\n", fe->id);
		return -1;
	}

	return open_fe_fd(&rfi->d);
}

int self_exe_fd;

static int restore_exe_early(struct fdinfo_entry *fe, int fd)
{
	int tmp;

	/*
	 * We restore the EXE symlink at very late stage
	 * because of restrictions applied from kernel side,
	 * so keep this fd open till then.
	 */

	self_exe_fd = get_service_fd(SELF_EXE_FD_OFF);
	if (self_exe_fd < 0)
		return self_exe_fd;

	tmp = find_open_fe_fd(fe);
	if (tmp < 0)
		return tmp;

	return reopen_fd_as(self_exe_fd, tmp);
}

static void transport_name_gen(struct sockaddr_un *addr, int *len,
		int pid, long fd)
{
	addr->sun_family = AF_UNIX;
	snprintf(addr->sun_path, UNIX_PATH_MAX, "x/crtools-fd-%d-%ld", pid, fd);
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
		if (fle->fd == fe->addr) {
			/* file master */
			if (!should_open_transport(fe, d))
				return 0;
		} else
			return 0;
	}

	transport_name_gen(&saddr, &sun_len, getpid(), fe->addr);

	pr_info("\t%d: Create transport fd for %lx\n", pid, fe->addr);

	list_for_each_entry(fle, &d->fd_info_head, list)
		if ((fle->pid == pid) && (fle->fd == fe->addr))
			break;

	BUG_ON(&d->fd_info_head == &fle->list);

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

	ret = reopen_fd_as((int)fe->addr, sock);
	if (ret < 0)
		return -1;

	pr_info("Wake up fdinfo pid=%d fd=%d\n", fle->pid, fle->fd);
	futex_set_and_wake(&fle->real_pid, getpid());

	return 0;
}

int send_fd_to_peer(int fd, struct fdinfo_list_entry *fle, int tsk)
{
	struct sockaddr_un saddr;
	int len;

	pr_info("Wait fdinfo pid=%d fd=%d\n", fle->pid, fle->fd);
	futex_wait_while(&fle->real_pid, 0);
	transport_name_gen(&saddr, &len,
			futex_get(&fle->real_pid), fle->fd);
	pr_info("Send fd %d to %s\n", fd, saddr.sun_path + 1);
	return send_fd(tsk, &saddr, len, fd);
}

static int open_fd(int pid, struct fdinfo_entry *fe,
		struct file_desc *d, int *fdinfo_fd)
{
	int tmp;
	int serv, sock;
	struct fdinfo_list_entry *fle;

	fle = file_master(d);
	if ((fle->pid != pid) || (fe->addr != fle->fd))
		return 0;

	tmp = d->ops->open(d);
	if (tmp < 0)
		return -1;

	if (reopen_fd_as((int)fe->addr, tmp))
		return -1;

	sock = socket(PF_UNIX, SOCK_DGRAM, 0);
	if (sock < 0) {
		pr_perror("Can't create socket");
		return -1;
	}

	pr_info("\t%d: Create fd for %lx\n", pid, fe->addr);

	list_for_each_entry(fle, &d->fd_info_head, list) {
		if (pid == fle->pid) {
			pr_info("\t\tGoing to dup %d into %d\n",
					(int)fe->addr, fle->fd);
			if (fe->addr == fle->fd)
				continue;

			if (move_img_fd(&sock, fle->fd))
				return -1;
			if (move_img_fd(fdinfo_fd, fle->fd))
				return -1;

			if (dup2(fe->addr, fle->fd) != fle->fd) {
				pr_perror("Can't dup local fd %d -> %d",
						(int)fe->addr, fle->fd);
				return -1;
			}

			continue;
		}

		if (send_fd_to_peer(fe->addr, fle, sock)) {
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

	pr_info("\t%d: Receive fd for %lx\n", pid, fe->addr);

	tmp = recv_fd(fe->addr);
	if (tmp < 0) {
		pr_err("Can't get fd %d\n", tmp);
		return -1;
	}
	close(fe->addr);

	return reopen_fd_as((int)fe->addr, tmp);
}

static int open_fdinfo(int pid, struct fdinfo_entry *fe, int *fdinfo_fd, int state)
{
	u32 mag;
	int ret = 0;
	struct file_desc *fdesc;

	fdesc = find_file_desc(fe);
	if (move_img_fd(fdinfo_fd, (int)fe->addr))
		return -1;

	pr_info("\t%d: Got fd for %lx\n", pid, fe->addr);

	BUG_ON(fd_is_special(fe));

	switch (state) {
	case FD_STATE_PREP:
		ret = open_transport_fd(pid, fe, fdesc);
		break;
	case FD_STATE_CREATE:
		ret = open_fd(pid, fe, fdesc, fdinfo_fd);
		break;
	case FD_STATE_RECV:
		ret = receive_fd(pid, fe, fdesc);
		break;
	}

	return ret;
}

static int open_special_fdinfo(int pid, struct fdinfo_entry *fe,
		int fdinfo_fd, int state)
{
	if (state != FD_STATE_RECV)
		return 0;

	if (fe->type == FDINFO_EXE)
		return restore_exe_early(fe, fdinfo_fd);

	pr_info("%d: fe->type: %d\n", pid,  fe->type);
	BUG_ON(1);
	return -1;
}

int prepare_fds(int pid)
{
	u32 type = 0, ret;
	int fdinfo_fd;
	int state;
	off_t offset, magic_offset;

	struct fdinfo_entry fe;
	int nr = 0;

	pr_info("%d: Opening fdinfo-s\n", pid);

	fdinfo_fd = open_image_ro(CR_FD_FDINFO, pid);
	if (fdinfo_fd < 0) {
		pr_perror("%d: Can't open pipes img", pid);
		return -1;
	}

	magic_offset = lseek(fdinfo_fd, 0, SEEK_CUR);

	for (state = 0; state < FD_STATE_MAX; state++) {
		lseek(fdinfo_fd, magic_offset, SEEK_SET);

		while (1) {
			ret = read_img_eof(fdinfo_fd, &fe);
			if (ret <= 0)
				break;

			if (fd_is_special(&fe))
				ret = open_special_fdinfo(pid, &fe,
						fdinfo_fd, state);
			else
				ret = open_fdinfo(pid, &fe, &fdinfo_fd, state);

			if (ret)
				break;
		}

		if (ret)
			break;
	}

	close(fdinfo_fd);

	return run_unix_connections();
}

int prepare_fs(int pid)
{
	int ifd, cwd;
	struct fs_entry fe;
	struct file_desc *fd;

	ifd = open_image_ro(CR_FD_FS, pid);
	if (ifd < 0)
		return -1;

	if (read_img(ifd, &fe) < 0)
		return -1;

	fd = find_file_desc_raw(FDINFO_REG, fe.cwd_id);
	if (fd == NULL) {
		pr_err("Can't find file for %d's cwd (%x)\n",
				pid, fe.cwd_id);
		return -1;
	}

	cwd = open_fe_fd(fd);
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
	struct file_desc *fd;

	fd = find_file_desc_raw(FDINFO_REG, vma_entry->shmid);
	if (fd == NULL) {
		pr_err("Can't find file for mapping %lx-%lx\n",
				vma_entry->start, vma_entry->end);
		return -1;
	}

	return open_fe_fd(fd);
}
