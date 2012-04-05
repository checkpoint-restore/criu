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

static struct fmap_fd *fmap_fds;

int prepare_shared_fdinfo(void)
{
	fdinfo_list = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANON, 0, 0);
	if (fdinfo_list == MAP_FAILED) {
		pr_perror("Can't map fdinfo_list");
		return -1;
	}
	return 0;
}

struct reg_file_info {
	struct reg_file_entry rfe;
	char *path;
	struct list_head list;
	struct list_head fd_head;
};

#define REG_FILES_HSIZE	32
static struct list_head reg_files[REG_FILES_HSIZE];

void show_saved_files(void)
{
	int i;
	struct reg_file_info *rfi;

	pr_info("Reg files:\n");
	for (i = 0; i < REG_FILES_HSIZE; i++)
		list_for_each_entry(rfi, &reg_files[i], list) {
			struct fdinfo_list_entry *le;

			pr_info(" `- ID %x\n", rfi->rfe.id);
			list_for_each_entry(le, &rfi->fd_head, list)
				pr_info("   `- FD %d pid %d\n", le->fd, le->pid);
		}
}

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

static struct list_head *find_reg_fd(int id)
{
	struct reg_file_info *rfi;

	rfi = find_reg_file(id);
	return &rfi->fd_head;
}

static struct list_head *find_fi_list(struct fdinfo_entry *fe)
{
	if (fe->type == FDINFO_REG)
		return find_reg_fd(fe->id);
	if (fe->type == FDINFO_INETSK)
		return find_inetsk_fd(fe->id);
	if (fe->type == FDINFO_PIPE)
		return find_pipe_fd(fe->id);

	BUG_ON(1);
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
		INIT_LIST_HEAD(&rfi->fd_head);
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
	struct fdinfo_list_entry *l, *le = &fdinfo_list[nr_fdinfo_list];
	struct list_head *fi_list;

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

	fi_list = find_fi_list(e);
	if (fi_list == NULL) {
		pr_err("No file for fd %d id %d\n", (int)e->addr, e->id);
		return -1;
	}

	list_for_each_entry(l, fi_list, list)
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

static int open_fe_fd(struct list_head *l)
{
	struct reg_file_info *rfi;
	int tmp;

	rfi = container_of(l, struct reg_file_info, fd_head);

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

	return open_fe_fd(&rfi->fd_head);
}

static int restore_cwd(struct fdinfo_entry *fe, int fd)
{
	int cfd;

	cfd = find_open_fe_fd(fe);
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

	tmp = find_open_fe_fd(fe);
	if (tmp < 0)
		return tmp;

	return reopen_fd_as(self_exe_fd, tmp);
}

void transport_name_gen(struct sockaddr_un *addr, int *len,
		int pid, long fd)
{
	addr->sun_family = AF_UNIX;
	snprintf(addr->sun_path, UNIX_PATH_MAX, "x/crtools-fd-%d-%ld", pid, fd);
	*len = SUN_LEN(addr);
	*addr->sun_path = '\0';
}

static int should_open_transport(struct fdinfo_entry *fe, struct list_head *fd_list)
{
	if (fe->type == FDINFO_PIPE)
		return pipe_should_open_transport(fe, fd_list);

	return 0;
}

static int open_transport_fd(int pid, struct fdinfo_entry *fe, struct list_head *fd_list)
{
	struct fdinfo_list_entry *fle;
	struct sockaddr_un saddr;
	int sock;
	int ret, sun_len;

	fle = file_master(fd_list);

	if (fle->pid == pid) {
		if (fle->fd == fe->addr) {
			/* file master */
			if (!should_open_transport(fe, fd_list))
				return 0;
		} else
			return 0;
	}

	transport_name_gen(&saddr, &sun_len, getpid(), fe->addr);

	pr_info("\t%d: Create transport fd for %lx\n", pid, fe->addr);

	list_for_each_entry(fle, fd_list, list)
		if ((fle->pid == pid) && (fle->fd == fe->addr))
			break;

	BUG_ON(fd_list == &fle->list);

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
		struct list_head *fd_list, int *fdinfo_fd)
{
	int tmp;
	int serv, sock;
	struct sockaddr_un saddr;
	struct fdinfo_list_entry *fle;

	fle = file_master(fd_list);
	if ((fle->pid != pid) || (fe->addr != fle->fd))
		return 0;

	switch (fe->type) {
	case FDINFO_REG:
		tmp = open_fe_fd(fd_list);
		break;
	case FDINFO_INETSK:
		tmp = open_inet_sk(fd_list);
		break;
	case FDINFO_PIPE:
		tmp = open_pipe(fd_list);
		break;
	default:
		tmp = -1;
		break;
	}

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

	list_for_each_entry(fle, fd_list, list) {
		int len;

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

static int receive_fd(int pid, struct fdinfo_entry *fe, struct list_head *fd_list)
{
	int tmp;
	struct fdinfo_list_entry *fle;

	fle = file_master(fd_list);

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

static int open_fmap(int pid, struct fdinfo_entry *fe, int fd)
{
	struct fmap_fd *new;
	int tmp;

	tmp = find_open_fe_fd(fe);
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
	struct list_head *fi_list;

	fi_list = find_fi_list(fe);
	if (move_img_fd(fdinfo_fd, (int)fe->addr))
		return -1;

	pr_info("\t%d: Got fd for %lx\n", pid, fe->addr);

	BUG_ON(fd_is_special(fe));

	switch (state) {
	case FD_STATE_PREP:
		ret = open_transport_fd(pid, fe, fi_list);
		break;
	case FD_STATE_CREATE:
		ret = open_fd(pid, fe, fi_list, fdinfo_fd);
		break;
	case FD_STATE_RECV:
		ret = receive_fd(pid, fe, fi_list);
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
