#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "crtools.h"
#include "image.h"
#include "files.h"
#include "pipes.h"
#include "util-net.h"

/* The sequence of objects which should be restored:
 * pipe -> files struct-s -> fd-s.
 * pipe_entry describes  pipe's file structs-s.
 * A pipe doesn't have own properties, so it has no object.
 */

struct pipe_info {
	struct pipe_entry pe;
	struct list_head pipe_list;	/* all pipe_info with the same pipe_id
					 * This is pure circular list without head */
	struct list_head list;		/* list head for fdinfo_list_entry-s */
	struct file_desc d;
	int create;
	int bytes;
	off_t off;
};

static LIST_HEAD(pipes);

static int open_pipe(struct file_desc *d);
static int pipe_should_open_transport(struct fdinfo_entry *fe,
		struct file_desc *d);

static struct file_desc_ops pipe_desc_ops = {
	.type = FDINFO_PIPE,
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
		pi = xmalloc(sizeof(*pi));
		ret = -1;
		if (pi == NULL)
			break;

		ret = read_img_eof(fd, &pi->pe);
		if (ret <= 0)
			break;

		pr_info("Collected pipe entry ID %#x PIPE ID %#x\n",
					pi->pe.id, pi->pe.pipe_id);

		file_desc_add(&pi->d, pi->pe.id, &pipe_desc_ops);

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

	pr_info("  `- ID %p %#xpn", pi, pi->pe.id);
	list_for_each_entry(fle, &pi->d.fd_info_head, desc_list)
		pr_info("   `- FD %d pid %d\n", fle->fe.fd, fle->pid);
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

		pr_info(" `- PIPE ID %#x\n", pi->pe.pipe_id);
		show_saved_pipe_fds(pi);

		fle = file_master(&pi->d);
		p = pi;
		fd = fle->fe.fd;
		pid = fle->pid;

		list_for_each_entry(pic, &pi->pipe_list, pipe_list) {
			list_move(&pic->list, &head);

			fle = file_master(&p->d);
			if (fle->pid < pid ||
			    (pid == fle->pid && fle->fe.fd < fd)) {
				p = pic;
				fd = fle->fe.fd;
				pid = fle->pid;
			}

			show_saved_pipe_fds(pic);
		}
		p->create = 1;
		pr_info("    by %#x\n", p->pe.id);
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
	fd = fle->fe.fd;

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

	if (restore_fown(fd, &pi->pe.fown))
		return -1;

	return fd;
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
			pr_perror("%#x: Error splicing data", pi->pe.id);
			goto err;
		}

		if (ret == 0) {
			pr_err("%#x: Wanted to restore %d bytes, but got %d\n",
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
	struct pipe_info *pi, *p;
	int ret, tmp;
	int pfd[2];
	int sock;

	pi = container_of(d, struct pipe_info, d);

	pr_info("\t\tCreating pipe pipe_id=%#x id=%#x\n", pi->pe.pipe_id, pi->pe.id);

	if (!pi->create)
		return recv_pipe_fd(pi);

	if (pipe(pfd) < 0) {
		pr_perror("Can't create pipe");
		return -1;
	}

	ret = restore_pipe_data(pfd[1], pi);
	if (ret)
		return -1;

	sock = socket(PF_UNIX, SOCK_DGRAM, 0);
	if (sock < 0) {
		pr_perror("Can't create socket");
		return -1;
	}

	list_for_each_entry(p, &pi->pipe_list, pipe_list) {
		struct fdinfo_list_entry *fle;
		int fd;

		fle = file_master(&p->d);
		fd = pfd[p->pe.flags & O_WRONLY];

		if (send_fd_to_peer(fd, fle, sock)) {
			pr_perror("Can't send file descriptor");
			return -1;
		}
	}

	close(sock);

	close(pfd[!(pi->pe.flags & O_WRONLY)]);
	tmp = pfd[pi->pe.flags & O_WRONLY];

	if (rst_file_params(tmp, &pi->pe.fown, pi->pe.flags))
		return -1;

	return tmp;
}

#define PIPES_SIZE 1024
static u32 *pipes_with_data;	/* pipes for which data already dumped */
static int nr_pipes = 0;

static int dump_one_pipe(int lfd, u32 id, const struct fd_parms *p)
{
	struct pipe_entry pe;
	int fd_pipes;
	int steal_pipe[2];
	int pipe_size;
	int has_bytes = 0;
	int ret = -1;
	int i = 0;

	pr_info("Dumping pipe %d with id %#x pipe_id %#x\n", lfd, id, p->id);

	fd_pipes = fdset_fd(glob_fdset, CR_FD_PIPES);

	if (p->flags & O_WRONLY)
		goto dump;

	for (i = 0; i < nr_pipes; i++)
		if (pipes_with_data[i] == p->id)
			goto dump; /* data was dumped already */

	nr_pipes++;
	if (nr_pipes > PIPES_SIZE) {
		pr_err("OOM storing pipe\n");
		return -1;
	}

	pr_info("Dumping data from pipe %#x fd %d\n", id, lfd);

	pipes_with_data[nr_pipes - 1] = p->id;

	pipe_size = fcntl(lfd, F_GETPIPE_SZ);
	if (pipe_size < 0) {
		pr_err("Can't obtain piped data size\n");
		goto err;
	}

	if (pipe(steal_pipe) < 0) {
		pr_perror("Can't create pipe for stealing data");
		goto err;
	}

	has_bytes = tee(lfd, steal_pipe[1], pipe_size, SPLICE_F_NONBLOCK);
	if (has_bytes < 0) {
		if (errno != EAGAIN) {
			pr_perror("Can't pick pipe data");
			goto err_close;
		} else
			has_bytes = 0;
	}
dump:
	pe.id = id;
	pe.pipe_id = p->id;
	pe.flags = p->flags;
	pe.fown = p->fown;

	if (write_img(fd_pipes, &pe))
		goto err_close;

	if (has_bytes) {
		off_t off;
		struct pipe_data_entry pde;

		fd_pipes = fdset_fd(glob_fdset, CR_FD_PIPES_DATA);

		pde.pipe_id = p->id;
		pde.bytes = has_bytes;
		pde.off = 0;

		if (has_bytes > PIPE_NONALIG_DATA) {
			off = lseek(fd_pipes, 0, SEEK_CUR);
			off += sizeof(pde);
			off &= PAGE_SIZE -1;
			if (off)
				pde.off = PAGE_SIZE - off;
			pr_info("off 0x%lx %#x\n", off, pde.off);
		}

		if (write_img(fd_pipes, &pde))
			goto err_close;

		if (pde.off) {
			off = lseek(fd_pipes, pde.off, SEEK_CUR);
			pr_info("off 0x%lx\n", off);
		}

		ret = splice(steal_pipe[0], NULL, fd_pipes,
			     NULL, has_bytes, 0);
		if (ret < 0) {
			pr_perror("Can't push pipe data");
			goto err_close;
		}
	}

	ret = 0;

err_close:
	if (has_bytes) {
		close(steal_pipe[0]);
		close(steal_pipe[1]);
	}
err:
	return ret;
}

static const struct fdtype_ops pipe_ops = {
	.type		= FDINFO_PIPE,
	.make_gen_id	= make_gen_id,
	.dump		= dump_one_pipe,
};

int dump_pipe(struct fd_parms *p, int lfd,
			     const struct cr_fdset *cr_fdset)
{
	return do_dump_gen_file(p, lfd, &pipe_ops, cr_fdset);
}

int init_pipes_dump(void)
{
	pipes_with_data = xmalloc(PIPES_SIZE * sizeof(*pipes_with_data));
	return pipes_with_data == NULL ? -1 : 0;
}

void fini_pipes_dump(void)
{
	xfree(pipes_with_data);
}
