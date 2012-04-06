#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "crtools.h"
#include "image.h"
#include "files.h"
#include "util-net.h"

/* The sequence of objects which should be restored:
 * pipe -> files struct-s -> fd-s.
 * pipe_entry describes  pipe's file structs-s.
 * A pipe has not own properties, so it has not own object.
 */

struct pipe_info {
	struct pipe_entry pe;
	struct list_head pipe_list;	/* all pipe_info with the same pipe_id
					 * This is pure circular list whiout head */
	struct list_head list;		/* list head for fdinfo_list_entry-s */
	struct file_desc d;
	int create;
	int bytes;
	off_t off;
};

static LIST_HEAD(pipes);

static struct pipe_info *find_pipe(int id)
{
	struct file_desc *fd;

	fd = find_file_desc_raw(FDINFO_PIPE, id);
	return container_of(fd, struct pipe_info, d);
}

static int open_pipe(struct file_desc *d);
static int pipe_should_open_transport(struct fdinfo_entry *fe,
		struct file_desc *d);

static struct file_desc_ops pipe_desc_ops = {
	.open = open_pipe,
	.want_transport = pipe_should_open_transport,
};

int collect_pipes(void)
{
	struct pipe_info *pi = NULL, *tmp;
	int fd, ret = -1;

	fd = open_image_ro(CR_FD_PIPES);
	if (fd < 0)
		return -1;

	while (1) {
		int len;

		pi = xmalloc(sizeof(*pi));
		ret = -1;
		if (pi == NULL)
			break;

		ret = read_img_eof(fd, &pi->pe);
		if (ret <= 0)
			break;

		pr_info("Collected pipe entry ID %x PIPE ID %x\n",
					pi->pe.id, pi->pe.pipe_id);

		file_desc_add(&pi->d, FDINFO_PIPE, pi->pe.id,
				&pipe_desc_ops);

		list_for_each_entry(tmp, &pipes, list)
			if (pi->pe.pipe_id == tmp->pe.pipe_id)
				break;

		if (&tmp->list == &pipes)
			INIT_LIST_HEAD(&pi->pipe_list);
		else
			list_add(&pi->pipe_list, &tmp->pipe_list);

		list_add_tail(&pi->list, &pipes);
	}

	xfree(pi);

	close(fd);
	return ret;
}

static void show_saved_pipe_fds(struct pipe_info *pi)
{
	struct fdinfo_list_entry *fle;

	pr_info("  `- ID %p %xpn", pi, pi->pe.id);
	list_for_each_entry(fle, &pi->d.fd_info_head, list)
		pr_info("   `- FD %d pid %d\n", fle->fd, fle->pid);
}

static int handle_pipes_data()
{
	int fd, ret;

	fd = open_image_ro(CR_FD_PIPES_DATA);
	if (fd < 0)
		return -1;

	while (1) {
		struct pipe_info *pi;
		struct pipe_data_entry pde;

		ret = read_img_eof(fd, &pde);
		if (ret < 0)
			goto err;

		if (ret == 0)
			break;

		list_for_each_entry(pi, &pipes, list) {
			if (pi->pe.pipe_id != pde.pipe_id)
				continue;
			if (!pi->create)
				continue;

			pi->off = lseek(fd, 0, SEEK_CUR) + pde.off;
			pi->bytes = pde.bytes;

			lseek(fd, pde.bytes + pde.off, SEEK_CUR);
			break;
		}
	}
err:
	close(fd);
	return ret;
}

/* Choose who will restore a pipe. */
void mark_pipe_master()
{
	LIST_HEAD(head);

	pr_info("Pipes:\n");

	while (1) {
		struct fdinfo_list_entry *fle;
		struct pipe_info *pi, *pic, *p;
		int fd, pid;

		if (list_empty(&pipes))
			break;

		pi = list_first_entry(&pipes, struct pipe_info, list);
		list_move(&pi->list, &head);

		pr_info(" `- PIPE ID %x\n", pi->pe.pipe_id);
		show_saved_pipe_fds(pi);

		fle = file_master(&pi->d);
		p = pi;
		fd = fle->fd;
		pid = fle->pid;

		list_for_each_entry(pic, &pi->pipe_list, pipe_list) {
			list_move(&pic->list, &head);

			fle = file_master(&p->d);
			if (fle->pid < pid ||
			    (pid == fle->pid && fle->fd < fd)) {
				p = pic;
				fd = fle->fd;
				pid = fle->pid;
			}

			show_saved_pipe_fds(pic);
		}
		p->create = 1;
		pr_info("    by %x\n", p->pe.id);
	}

	list_splice(&head, &pipes);

	handle_pipes_data();
}

static int pipe_should_open_transport(struct fdinfo_entry *fe,
		struct file_desc *d)
{
	struct pipe_info *pi;
	
	pi = container_of(d, struct pipe_info, d);
	return !pi->create;
}

static int recv_pipe_fd(struct pipe_info *pi)
{
	struct fdinfo_list_entry *fle;
	char path[PATH_MAX];
	int tmp, fd;

	fle = file_master(&pi->d);
	fd = fle->fd;

	pr_info("\tWaiting fd for %d\n", fd);

	tmp = recv_fd(fd);
	if (tmp < 0) {
		pr_err("Can't get fd %d\n", tmp);
		return -1;
	}
	close(fd);

	snprintf(path, PATH_MAX, "/proc/self/fd/%d", tmp);
	fd = open(path, pi->pe.flags);
	close(tmp);

	return fd;
}

#define SETFL_MASK (O_APPEND | O_NONBLOCK | O_NDELAY | O_DIRECT | O_NOATIME)
static int set_fd_flags(int fd, int flags)
{
	int old;

	old = fcntl(fd, F_GETFL, 0);
	if (old < 0)
		return old;

	flags = (SETFL_MASK & flags) | (old & ~SETFL_MASK);

	return fcntl(fd, F_SETFL, flags);
}

static int restore_pipe_data(int pfd, struct pipe_info *pi)
{
	int fd, size = 0, ret;

	fd = open_image_ro(CR_FD_PIPES_DATA);
	if (fd < 0)
		return -1;

	lseek(fd, pi->off, SEEK_SET);

	pr_info("\t\tSplicing data size=%d off=%ld\n", pi->bytes, pi->off);

	while (size != pi->bytes) {
		ret = splice(fd, NULL, pfd, NULL, pi->bytes - size, 0);
		if (ret < 0) {
			pr_perror("%x: Error splicing data", pi->pe.id);
			goto err;
		}

		if (ret == 0) {
			pr_err("%x: Wanted to restore %d bytes, but got %d\n",
				pi->pe.id, pi->bytes, size);
			ret = -1;
			goto err;
		}

		size += ret;
	}

	ret = 0;
err:
	close(fd);
	return ret;
}

static int open_pipe(struct file_desc *d)
{
	unsigned long time = 1000;
	struct pipe_info *pi, *pc, *p;
	int ret, tmp;
	int pfd[2];
	int sock;
	int create;

	pi = container_of(d, struct pipe_info, d);

	pr_info("\tCreating pipe pipe_id=%x id=%x\n", pi->pe.pipe_id, pi->pe.id);

	if (!pi->create)
		return recv_pipe_fd(pi);

	if (pipe(pfd) < 0) {
		pr_perror("Can't create pipe");
		return -1;
	}

	ret = restore_pipe_data(pfd[1], pi);

	sock = socket(PF_UNIX, SOCK_DGRAM, 0);
	if (sock < 0) {
		pr_perror("Can't create socket");
		return -1;
	}

	list_for_each_entry(p, &pi->pipe_list, pipe_list) {
		int len, fd;
		struct sockaddr_un saddr;
		struct fdinfo_list_entry *fle;

		fle = file_master(&p->d);

		pr_info("\t\tWait fdinfo pid=%d fd=%d\n", fle->pid, fle->fd);
		futex_wait_while(&fle->real_pid, 0);

		transport_name_gen(&saddr, &len,
				futex_get(&fle->real_pid), fle->fd);

		fd = pfd[p->pe.flags & O_WRONLY];

		pr_info("\t\tSend fd %d to %s\n", fd, saddr.sun_path + 1);

		if (send_fd(sock, &saddr, len, fd) < 0) {
			pr_perror("Can't send file descriptor");
			return -1;
		}
	}

	close(sock);

out:
	close(pfd[!(pi->pe.flags & O_WRONLY)]);
	tmp = pfd[pi->pe.flags & O_WRONLY];
	ret = set_fd_flags(tmp, pi->pe.flags);
	if (ret < 0)
		return -1;

	return tmp;
}
