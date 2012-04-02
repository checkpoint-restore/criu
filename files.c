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

static struct fdinfo_desc *fdinfo_descs;
static int nr_fdinfo_descs;

static struct fdinfo_list_entry *fdinfo_list;
static int nr_fdinfo_list;

static struct fmap_fd *fmap_fds;

int prepare_shared_fdinfo(void)
{
	fdinfo_descs = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANON, 0, 0);
	if (fdinfo_descs == MAP_FAILED) {
		pr_perror("Can't map fdinfo_descs");
		return -1;
	}

	fdinfo_list = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANON, 0, 0);
	if (fdinfo_list == MAP_FAILED) {
		pr_perror("Can't map fdinfo_list");
		return -1;
	}
	return 0;
}

static struct fdinfo_desc *find_fd(struct fdinfo_entry *fe)
{
	struct fdinfo_desc *fi;
	int i;

	for (i = 0; i < nr_fdinfo_descs; i++) {
		fi = fdinfo_descs + i;
		if ((fi->id == fe->id) && (fi->type == fe->type))
			return fi;
	}

	return NULL;
}

struct reg_file_info {
	struct reg_file_entry rfe;
	char *path;
	struct list_head list;
};

#define REG_FILES_HSIZE	32
static struct list_head reg_files[REG_FILES_HSIZE];

static struct reg_file_info *find_reg_file(int id)
{
	int chain;
	struct reg_file_info *rfi;

	chain = id % REG_FILES_HSIZE;
	list_for_each_entry(rfi, &reg_files[chain], list)
		if (rfi->rfe.id == id)
			return rfi;
	return NULL;
}

int collect_reg_files(void)
{
	struct reg_file_info *rfi = NULL;
	int fd, ret = -1, chain;

	for (chain = 0; chain < REG_FILES_HSIZE; chain++)
		INIT_LIST_HEAD(&reg_files[chain]);

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
		chain = rfi->rfe.id % REG_FILES_HSIZE;
		list_add_tail(&rfi->list, &reg_files[chain]);
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
	struct fdinfo_list_entry *le = &fdinfo_list[nr_fdinfo_list];
	struct fdinfo_desc *desc;

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

	for (i = 0; i < nr_fdinfo_descs; i++) {
		desc = &fdinfo_descs[i];

		if ((desc->id != e->id) || (desc->type != e->type))
			continue;

		list_add(&le->list, &desc->list);

		if (fdinfo_descs[i].pid < pid)
			return 0;

		desc->pid = pid;
		desc->addr = e->addr;

		return 0;
	}

	if ((nr_fdinfo_descs + 1) * sizeof(struct fdinfo_desc) >= 4096) {
		pr_err("OOM storing fdinfo descriptions\n");
		return -1;
	}

	desc = &fdinfo_descs[nr_fdinfo_descs];
	memzero(desc, sizeof(*desc));

	desc->id	= e->id;
	desc->type	= e->type;
	desc->addr	= e->addr;
	desc->pid	= pid;
	INIT_LIST_HEAD(&desc->list);

	list_add(&le->list, &desc->list);
	nr_fdinfo_descs++;

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

static int open_fe_fd(struct fdinfo_entry *fe)
{
	struct reg_file_info *rfi;
	int tmp;

	rfi = find_reg_file(fe->id);
	if (!rfi) {
		pr_err("Can't find file id %x\n", fe->id);
		return -1;
	}

	tmp = open(rfi->path, rfi->rfe.flags);
	if (tmp < 0) {
		pr_perror("Can't open file %s", rfi->path);
		return -1;
	}

	lseek(tmp, rfi->rfe.pos, SEEK_SET);

	return tmp;
}

static int restore_cwd(struct fdinfo_entry *fe, int fd)
{
	int cfd;

	cfd = open_fe_fd(fe);
	if (cfd < 0)
		return cfd;

	if (fchdir(cfd)) {
		pr_perror("Can't chdir");
		return -1;
	}

	close(cfd);
	return 0;
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

	tmp = open_fe_fd(fe);
	if (tmp < 0)
		return tmp;

	return reopen_fd_as(self_exe_fd, tmp);
}

struct fdinfo_list_entry *find_fdinfo_list_entry(int pid, int fd, struct fdinfo_desc *fi)
{
	struct fdinfo_list_entry *fle;
	int found = 0;

	list_for_each_entry(fle, &fi->list, list) {
		if (fle->fd == fd && fle->pid == pid) {
			found = 1;
			break;
		}
	}

	BUG_ON(found == 0);
	return fle;
}

static inline void transport_name_gen(struct sockaddr_un *addr, int *len,
		int pid, long fd)
{
	addr->sun_family = AF_UNIX;
	snprintf(addr->sun_path, UNIX_PATH_MAX, "x/crtools-fd-%d-%ld", pid, fd);
	*len = SUN_LEN(addr);
	*addr->sun_path = '\0';
}

static int open_transport_fd(int pid, struct fdinfo_entry *fe,
				struct fdinfo_desc *fi)
{
	struct fdinfo_list_entry *fle;
	struct sockaddr_un saddr;
	int sock;
	int ret, sun_len;

	if (fi->pid == pid)
		return 0;

	transport_name_gen(&saddr, &sun_len, getpid(), fe->addr);

	pr_info("\t%d: Create transport fd for %lx\n", pid, fe->addr);

	fle = find_fdinfo_list_entry(pid, fe->addr, fi);

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

static int open_fd(int pid, struct fdinfo_entry *fe,
				struct fdinfo_desc *fi, int fdinfo_fd)
{
	int tmp;
	int serv, sock;
	struct sockaddr_un saddr;
	struct fdinfo_list_entry *fle;

	if ((fi->pid != pid) || (fe->addr != fi->addr))
		return 0;

	switch (fe->type) {
	case FDINFO_REG:
		tmp = open_fe_fd(fe);
		break;
	case FDINFO_INETSK:
		tmp = open_inet_sk(fe);
		break;
	default:
		tmp = -1;
		break;
	}

	if (tmp < 0)
		return -1;

	if (reopen_fd_as((int)fe->addr, tmp))
		return -1;

	if (list_empty(&fi->list))
		goto out;

	sock = socket(PF_UNIX, SOCK_DGRAM, 0);
	if (sock < 0) {
		pr_perror("Can't create socket");
		return -1;
	}

	pr_info("\t%d: Create fd for %lx\n", pid, fe->addr);

	list_for_each_entry(fle, &fi->list, list) {
		int len;

		if (pid == fle->pid)
			continue;

		pr_info("Wait fdinfo pid=%d fd=%d\n", fle->pid, fle->fd);
		futex_wait_while(&fle->real_pid, 0);

		pr_info("Send fd %d to %s\n", (int)fe->addr, saddr.sun_path + 1);
		transport_name_gen(&saddr, &len, futex_get(&fle->real_pid), fle->fd);

		if (send_fd(sock, &saddr, len, fe->addr) < 0) {
			pr_perror("Can't send file descriptor");
			return -1;
		}
	}

	close(sock);
out:
	return 0;
}

static int receive_fd(int pid, struct fdinfo_entry *fe, struct fdinfo_desc *fi)
{
	int tmp;

	if (fi->pid == pid) {
		if (fi->addr != fe->addr) {
			tmp = dup2(fi->addr, fe->addr);
			if (tmp < 0) {
				pr_perror("Can't duplicate fd %ld %ld",
						fi->addr, fe->addr);
				return -1;
			}
		}

		return 0;
	}

	pr_info("\t%d: Receive fd for %lx\n", pid, fe->addr);

	tmp = recv_fd(fe->addr);
	if (tmp < 0) {
		pr_err("Can't get fd %d\n", tmp);
		return -1;
	}
	close(fe->addr);

	return reopen_fd_as((int)fe->addr, tmp);
}

static int open_fmap(int pid, struct fdinfo_entry *fe, int fd)
{
	struct fmap_fd *new;
	int tmp;

	tmp = open_fe_fd(fe);
	if (tmp < 0)
		return -1;

	pr_info("%d:\t\tWill map %lx to %d\n", pid, (unsigned long)fe->addr, tmp);

	new = xmalloc(sizeof(*new));
	if (!new) {
		close_safe(&tmp);
		return -1;
	}

	new->start	= fe->addr;
	new->fd		= tmp;
	new->next	= fmap_fds;
	new->pid	= pid;

	fmap_fds	= new;

	return 0;
}

static int open_fdinfo(int pid, struct fdinfo_entry *fe, int *fdinfo_fd, int state)
{
	u32 mag;
	int ret = 0;
	struct fdinfo_desc *fi = find_fd(fe);

	if (move_img_fd(fdinfo_fd, (int)fe->addr))
		return -1;

	pr_info("\t%d: Got fd for %lx\n", pid, fe->addr);

	BUG_ON(fd_is_special(fe));

	switch (state) {
	case FD_STATE_PREP:
		ret = open_transport_fd(pid, fe, fi);
		break;
	case FD_STATE_CREATE:
		ret = open_fd(pid, fe, fi, *fdinfo_fd);
		break;
	case FD_STATE_RECV:
		ret = receive_fd(pid, fe, fi);
		break;
	}

	return ret;
}

static int open_special_fdinfo(int pid, struct fdinfo_entry *fe,
		int fdinfo_fd, int state)
{
	if (state != FD_STATE_RECV)
		return 0;

	if (fe->type == FDINFO_MAP)
		return open_fmap(pid, fe, fdinfo_fd);
	if (fe->type == FDINFO_CWD)
		return restore_cwd(fe, fdinfo_fd);
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
	return ret;
}

static struct fmap_fd *pull_fmap_fd(int pid, unsigned long start)
{
	struct fmap_fd **p, *r;

	pr_info("%d: Looking for %lx : ", pid, start);

	for (p = &fmap_fds; *p != NULL; p = &(*p)->next) {
		if ((*p)->start != start || (*p)->pid != pid)
			continue;

		r = *p;
		*p = r->next;
		pr_info("found\n");

		return r;
	}

	pr_info("not found\n");
	return NULL;
}

int get_filemap_fd(int pid, struct vma_entry *vma_entry)
{
	struct fmap_fd *fmap_fd;
	
	fmap_fd = pull_fmap_fd(pid, vma_entry->start);
	return fmap_fd ? fmap_fd->fd : -1;
}
