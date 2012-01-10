#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#include <linux/limits.h>

#include <sys/types.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "crtools.h"

#include "files.h"
#include "image.h"
#include "list.h"
#include "util.h"
#include "lock.h"

#define UNIX_PATH_MAX (sizeof(struct sockaddr_un) - \
			(size_t)((struct sockaddr_un *) 0)->sun_path)

enum fdinfo_states {
	FD_STATE_PREP,		/* Create unix sockets */
	FD_STATE_CREATE,	/* Create and send fd */
	FD_STATE_RECV,		/* Receive fd */

	FD_STATE_MAX
};

struct fmap_fd {
	struct fmap_fd	*next;
	unsigned long	start;
	int		pid;
	int		fd;
};

struct fdinfo_desc {
	char		id[FD_ID_SIZE];
	u64		addr;
	int		pid;
	u32		real_pid;	/* futex */
	u32		users;		/* futex */
	struct list_head list;
};

struct fdinfo_list_entry {
	struct list_head	list;
	int			fd;
	int			pid;
	u32			real_pid;
};

static struct fdinfo_desc *fdinfo_descs;
static int nr_fdinfo_descs;

static struct fdinfo_list_entry *fdinfo_list;
static int nr_fdinfo_list;

static struct fmap_fd *fmap_fds;

static struct fdinfo_desc *find_fd(char *id)
{
	struct fdinfo_desc *fi;
	int i;

	for (i = 0; i < nr_fdinfo_descs; i++) {
		fi = fdinfo_descs + i;
		if (!strncmp(fi->id, id, FD_ID_SIZE))
			return fi;
	}

	return NULL;
}

static int get_file_path(char *path, struct fdinfo_entry *fe, int fd)
{
	if (read(fd, path, fe->len) != fe->len) {
		pr_err("Error reading path");
		return -1;
	}

	path[fe->len] = '\0';

	return 0;
}

int prepare_fdinfo_global()
{
	fdinfo_descs = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANON, 0, 0);
	if (fdinfo_descs == MAP_FAILED) {
		pr_perror("Can't map fdinfo_descs\n");
	if (prepare_fdinfo_global())
		return -1;
	}

	fdinfo_list = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANON, 0, 0);
	if (fdinfo_list == MAP_FAILED) {
		pr_perror("Can't map fdinfo_list\n");
		return -1;
	}
	return 0;
}

static int collect_fd(int pid, struct fdinfo_entry *e)
{
	int i;
	struct fdinfo_list_entry *le = &fdinfo_list[nr_fdinfo_list];
	struct fdinfo_desc	*desc;

	pr_info("Collect fdinfo pid=%d fd=%d id=%s\n", pid, e->addr, e->id);

	nr_fdinfo_list++;
	le->pid = pid;
	le->fd = e->addr;
	le->real_pid = 0;

	for (i = 0; i < nr_fdinfo_descs; i++) {
		desc = &fdinfo_descs[i];
		if (strncmp(desc->id, (char *) e->id, FD_ID_SIZE))
			continue;

		fdinfo_descs[i].users++;
		list_add(&le->list, &desc->list);

		if (fdinfo_descs[i].pid < pid)
			return 0;

		desc->pid = pid;
		desc->addr = e->addr;

		return 0;
	}

	if ((nr_fdinfo_descs + 1) * sizeof(struct fdinfo_desc) >= 4096) {
		pr_panic("OOM storing pipes\n");
		return -1;
	}

	desc = &fdinfo_descs[nr_fdinfo_descs];
	memset(desc, 0, sizeof(fdinfo_descs[nr_fdinfo_descs]));

	memcpy(desc->id, e->id, FD_ID_SIZE);
	desc->addr= e->addr;
	desc->pid = pid;
	desc->users = 1;
	INIT_LIST_HEAD(&desc->list);
	list_add(&le->list, &desc->list);
	nr_fdinfo_descs++;

	return 0;
}

int prepare_fd_pid(int pid)
{
	int fdinfo_fd;
	u32 type = 0;

	fdinfo_fd = open_image_ro(CR_FD_FDINFO, pid);
	if (fdinfo_fd < 0) {
		pr_perror("%d: Can't open fdinfo image\n", pid);
		return -1;
	}

	while (1) {
		int ret;
		struct fdinfo_entry e;

		ret = read(fdinfo_fd, &e, sizeof(e));
		if (ret == 0)
			break;
		if (ret != sizeof(e)) {
			pr_perror("%d: Read fdinfo failed %d (expected %li)\n",
				  pid, ret, sizeof(e));
			return -1;
		}
		if (e.len)
			lseek(fdinfo_fd, e.len, SEEK_CUR);

		if (e.type == FDINFO_MAP)
			continue;
		if (e.addr == -1)
			continue;
		if (collect_fd(pid, &e))
			return -1;
	}

	close(fdinfo_fd);
	return 0;
}

static int open_fe_fd(struct fdinfo_entry *fe, int fd)
{
	char path[PATH_MAX];
	int tmp;

	if (get_file_path(path, fe, fd))
		return -1;

	tmp = open(path, fe->flags);
	if (tmp < 0) {
		pr_perror("Can't open file %s\n", path);
		return -1;
	}

	lseek(tmp, fe->pos, SEEK_SET);

	return tmp;
}

static int restore_cwd(struct fdinfo_entry *fe, int fd)
{
	char path[PATH_MAX];
	int ret;

	if (get_file_path(path, fe, fd))
		return -1;

	pr_info("Restore CWD %s\n", path);
	ret = chdir(path);
	if (ret < 0) {
		pr_perror("Can't change dir %s\n", path);
		return -1;
	}

	return 0;
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

static int open_transport_fd(int pid, struct fdinfo_entry *fe,
				struct fdinfo_desc *fi, int *fdinfo_fd)
{
	struct fdinfo_list_entry *fle;
	struct sockaddr_un saddr;
	int sock;
	int ret, sun_len;

	saddr.sun_family = AF_UNIX;
	snprintf(saddr.sun_path, UNIX_PATH_MAX,
			"X/crtools-fd-%d-%ld", getpid(), fe->addr);

	sun_len = SUN_LEN(&saddr);
	*saddr.sun_path = '\0';

	pr_info("\t%d: Got fd for %lx type %d namelen %d users %d\n", pid,
			(unsigned long)fe->addr, fe->type, fe->len, fi->users);

	if (fi->pid == pid)
		return 0;

	fle = find_fdinfo_list_entry(pid, fe->addr, fi);

	sock = socket(PF_UNIX, SOCK_DGRAM, 0);
	if (sock < 0) {
		pr_perror("Can't create socket");
		return -1;
	}
	ret = bind(sock, &saddr, sun_len);
	if (ret < 0) {
		pr_perror("Can't bind unix socket %s\n", saddr.sun_path + 1);
		return -1;
	}

	ret = reopen_fd_as((int)fe->addr, sock);
	if (ret < 0)
		return -1;

	pr_info("Wake up fdinfo pid=%d fd=%d\n", fle->pid, fle->fd);
	cr_wait_set(&fle->real_pid, getpid());

	return 0;
}

static int open_fd(int pid, struct fdinfo_entry *fe,
				struct fdinfo_desc *fi, int *fdinfo_fd)
{
	int tmp;
	int serv, sock;
	struct sockaddr_un saddr;
	struct fdinfo_list_entry *fle;

	tmp = open_fe_fd(fe, *fdinfo_fd);
	if (tmp < 0)
		return -1;

	if (reopen_fd_as((int)fe->addr, tmp))
		return -1;

	if (!fi->users == 1)
		goto out;

	sock = socket(PF_UNIX, SOCK_DGRAM, 0);
	if (sock < 0) {
		pr_perror("Can't create socket");
		return -1;
	}

	cr_wait_set(&fi->real_pid, getpid());

	pr_info("\t%d: Got fd for %lx type %d namelen %d users %d\n", pid,
			(unsigned long)fe->addr, fe->type, fe->len, fi->users);

	list_for_each_entry(fle, &fi->list, list) {
		struct msghdr hdr;
		struct iovec data;
		char cmsgbuf[CMSG_SPACE(sizeof(int))];
		struct cmsghdr* cmsg;

		char dummy = '*';

		fi->users--;

		if (pid == fle->pid)
			continue;

		pr_info("Wait fdinfo pid=%d fd=%d\n", fle->pid, fle->fd);
		cr_wait_while(&fle->real_pid, 0);

		saddr.sun_family = AF_UNIX;
		snprintf(saddr.sun_path, UNIX_PATH_MAX,
				"X/crtools-fd-%d-%d", fle->real_pid, fle->fd);

		pr_info("Send fd %d to %s\n", fe->addr, saddr.sun_path + 1);

		data.iov_base = &dummy;
		data.iov_len = sizeof(dummy);

		hdr.msg_name = (struct sockaddr *)&saddr;
		hdr.msg_namelen = SUN_LEN(&saddr);
		*saddr.sun_path = '\0';
		hdr.msg_iov = &data;
		hdr.msg_iovlen = 1;
		hdr.msg_flags = 0;

		hdr.msg_control = &cmsgbuf;
		hdr.msg_controllen = CMSG_LEN(sizeof(int));

		cmsg = CMSG_FIRSTHDR(&hdr);
		cmsg->cmsg_len   = hdr.msg_controllen;
		cmsg->cmsg_level = SOL_SOCKET;
		cmsg->cmsg_type  = SCM_RIGHTS;

		*(int*)CMSG_DATA(cmsg) = fe->addr;

		tmp = sendmsg(sock, &hdr, 0);
		if (tmp < 0) {
			pr_perror("Can't send file descriptor");
			return -1;
		}
	}

	BUG_ON(fi->users);
	close(sock);
out:
	return 0;
}

static int recv_fd(int sock)
{
	struct msghdr msg;
	struct iovec iov;
	char buf[1];
	char ccmsg[CMSG_SPACE(sizeof(int))];
	struct cmsghdr *cmsg;
	iov.iov_base = buf;
	iov.iov_len = 1;
	int ret;

	msg.msg_name = 0;
	msg.msg_namelen = 0;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = ccmsg;
	msg.msg_controllen = sizeof(ccmsg);

	ret = recvmsg(sock, &msg, 0);
	if (ret == -1) {
		pr_perror("recvmsg");
		return -1;
	}

	cmsg = CMSG_FIRSTHDR(&msg);
	if (!cmsg->cmsg_type == SCM_RIGHTS) {
		pr_perror("got control message of unknown type %d\n",
							  cmsg->cmsg_type);
		return -1;
	}

	return *(int*)CMSG_DATA(cmsg);
}

static int receive_fd(int pid, struct fdinfo_entry *fe, struct fdinfo_desc *fi, int *fdinfo_fd)
{
	int tmp, fd;
	int sock;
	struct sockaddr_un saddr;
	socklen_t address_length;

	struct fdinfo_list_entry *fle;

	if (fi->pid == pid) {
		tmp = dup2(fi->addr, fe->addr);
		if (tmp < 0) {
			pr_perror("Can't duplicate fd %d %d\n", fi->addr, fe->addr);
			return -1;
		}
		return 0;
	}
	fle = find_fdinfo_list_entry(pid, fe->addr, fi);

	pr_info("\t%d: Got fd for %lx type %d namelen %d users %d\n", pid,
			(unsigned long)fe->addr, fe->type, fe->len, fi->users);

	tmp = recv_fd(fe->addr);
	if (tmp < 0) {
		pr_err("Can't get fd");
		return -1;
	}
	close(fe->addr);

	return reopen_fd_as((int)fe->addr, tmp);
}

static int open_fmap(int pid, struct fdinfo_entry *fe, int fd)
{
	int tmp;
	struct fmap_fd *new;

	tmp = open_fe_fd(fe, fd);
	if (tmp < 0)
		return -1;

	pr_info("%d:\t\tWill map %lx to %d\n", pid, (unsigned long)fe->addr, tmp);

	new		= malloc(sizeof(*new));
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
	int ret;

	struct fdinfo_desc *fi = find_fd((char *)fe->id);

	if (move_img_fd(fdinfo_fd, (int)fe->addr))
		return -1;

	pr_info("\t%d: Got fd for %lx type %d namelen %d users %d\n", pid,
			(unsigned long)fe->addr, fe->type, fe->len, fi->users);

	BUG_ON(fe->type != FDINFO_FD);


	if (pid == fi->pid && fe->addr == fi->addr) {
		if (state == FD_STATE_CREATE)
			ret = open_fd(pid, fe, fi, fdinfo_fd);
	} else {
		if (state == FD_STATE_PREP)
			ret = open_transport_fd(pid, fe, fi, fdinfo_fd);
		else if (state == FD_STATE_RECV)
			ret = receive_fd(pid, fe, fi, fdinfo_fd);
	}

	return ret;
}

int prepare_fds(int pid)
{
	u32 type = 0, err = -1, ret;
	int fdinfo_fd;
	int state;
	off_t offset, magic_offset;

	struct fdinfo_entry fe;
	int nr = 0;

	pr_info("%d: Opening fdinfo-s\n", pid);

	fdinfo_fd = open_image_ro(CR_FD_FDINFO, pid);
	if (fdinfo_fd < 0) {
		pr_perror("%d: Can't open pipes img\n", pid);
		return -1;
	}

	magic_offset = lseek(fdinfo_fd, 0, SEEK_CUR);

	for (state = 0; state < FD_STATE_MAX; state++) {
		lseek(fdinfo_fd, magic_offset, SEEK_SET);

		while (1) {
			ret = read(fdinfo_fd, &fe, sizeof(fe));
			if (ret == 0)
				break;

			if (ret != sizeof(fe)) {
				pr_perror("%d: Bad fdinfo entry\n", pid);
				goto err;
			}

			if (state == FD_STATE_RECV) {
				if (fe.type == FDINFO_MAP) {
					if (open_fmap(pid, &fe, fdinfo_fd))
						goto err;
					continue;
				} else if (fe.addr == ~0L) {
					if (restore_cwd(&fe, fdinfo_fd))
						goto err;
					continue;
				}
			} else if (fe.type == FDINFO_MAP || fe.addr == ~0L) {
				lseek(fdinfo_fd, fe.len, SEEK_CUR);
				continue;
			}

			offset = lseek(fdinfo_fd, 0, SEEK_CUR);

			if (open_fdinfo(pid, &fe, &fdinfo_fd, state))
				goto err;

			lseek(fdinfo_fd, offset + fe.len, SEEK_SET);
		}
	}
	err = 0;
err:
	close(fdinfo_fd);
	return err;
}

static struct fmap_fd *pop_fmap_fd(int pid, unsigned long start)
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

int try_fixup_file_map(int pid, struct vma_entry *vma_entry, int fd)
{
	struct fmap_fd *fmap_fd = pop_fmap_fd(pid, vma_entry->start);

	if (fmap_fd) {
		pr_info("%d: Fixing %lx vma to %d fd\n",
			pid, vma_entry->start, fmap_fd->fd);

		lseek(fd, -sizeof(*vma_entry), SEEK_CUR);
		vma_entry->fd = fmap_fd->fd;

		write_ptr_safe(fd, vma_entry, err);

		free(fmap_fd);
	}

	return 0;
err:
	pr_perror("%d: Can't fixup vma\n", pid);
	return -1;
}
