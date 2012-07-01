#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>

#include "crtools.h"
#include "image.h"
#include "files.h"
#include "pipes.h"
#include "util-net.h"

/*
 * The sequence of objects which should be restored:
 * pipe -> files struct-s -> fd-s.
 * pipe_entry describes  pipe's file structs-s.
 * A pipe doesn't have own properties, so it has no object.
 */

struct pipe_info {
	struct pipe_entry	pe;
	struct list_head	pipe_list;	/* All pipe_info with the same pipe_id
						 * This is pure circular list without head */
	struct list_head	list;		/* list head for fdinfo_list_entry-s */
	struct file_desc	d;
	int			create;
	int			bytes;
	off_t			off;
};

static LIST_HEAD(pipes);

static void show_saved_pipe_fds(struct pipe_info *pi)
{
	struct fdinfo_list_entry *fle;

	pr_info("  `- ID %p %#xpn", pi, pi->pe.id);
	list_for_each_entry(fle, &pi->d.fd_info_head, desc_list)
		pr_info("   `- FD %d pid %d\n", fle->fe->fd, fle->pid);
}

int collect_pipe_data(int img_type, struct pipe_data_rst **hash)
{
	int fd, ret;

	fd = open_image_ro(img_type);
	if (fd < 0)
		return -1;

	while (1) {
		struct pipe_data_rst *r;
		u32 off;

		ret = -1;
		r = xmalloc(sizeof(*r));
		if (!r)
			break;

		ret = read_img_eof(fd, &r->pde);
		if (ret <= 0)
			break;

		off = r->pde.off + lseek(fd, 0, SEEK_CUR);
		lseek(fd, r->pde.bytes + r->pde.off, SEEK_CUR);
		r->pde.off = off;

		ret = r->pde.pipe_id & PIPE_DATA_HASH_MASK;
		r->next = hash[ret];
		hash[ret] = r;

		pr_info("Collected pipe data for %#x (chain %u)\n",
				r->pde.pipe_id, ret);
	}

	close(fd);
	return ret;
}

/* Choose who will restore a pipe. */
void mark_pipe_master(void)
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
		fd = fle->fe->fd;
		pid = fle->pid;

		list_for_each_entry(pic, &pi->pipe_list, pipe_list) {
			list_move(&pic->list, &head);

			fle = file_master(&p->d);
			if (fle->pid < pid ||
			    (pid == fle->pid && fle->fe->fd < fd)) {
				p = pic;
				fd = fle->fe->fd;
				pid = fle->pid;
			}

			show_saved_pipe_fds(pic);
		}
		p->create = 1;
		pr_info("    by %#x\n", p->pe.id);
	}

	list_splice(&head, &pipes);
}

static struct pipe_data_rst *pd_hash_pipes[PIPE_DATA_HASH_SIZE];

int restore_pipe_data(int img_type, int pfd, u32 id, struct pipe_data_rst **hash)
{
	int img, size = 0, ret;
	struct pipe_data_rst *pd;

	for (pd = hash[id & PIPE_DATA_HASH_MASK]; pd != NULL; pd = pd->next)
		if (pd->pde.pipe_id == id)
			break;

	if (!pd) { /* no data for this pipe */
		pr_info("No data for pipe %#x\n", id);
		return 0;
	}

	img = open_image_ro(img_type);
	if (img < 0)
		return -1;

	pr_info("\t\tSplicing data size=%u off=%u\n", pd->pde.bytes, pd->pde.off);
	lseek(img, pd->pde.off, SEEK_SET);

	while (size != pd->pde.bytes) {
		ret = splice(img, NULL, pfd, NULL, pd->pde.bytes - size, 0);
		if (ret < 0) {
			pr_perror("%#x: Error splicing data", id);
			goto err;
		}

		if (ret == 0) {
			pr_err("%#x: Wanted to restore %d bytes, but got %d\n",
			       id, pd->pde.bytes, size);
			ret = -1;
			goto err;
		}

		size += ret;
	}

	ret = 0;
err:
	close(img);
	return ret;
}

static int recv_pipe_fd(struct pipe_info *pi)
{
	struct fdinfo_list_entry *fle;
	char path[PATH_MAX];
	int tmp, fd;

	fle = file_master(&pi->d);
	fd = fle->fe->fd;

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

	if (fd >= 0) {
		if (restore_fown(fd, &pi->pe.fown)) {
			close(fd);
			return -1;
		}
	}

	return fd;
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

	ret = restore_pipe_data(CR_FD_PIPES_DATA, pfd[1],
			pi->pe.pipe_id, pd_hash_pipes);
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

static int want_transport(struct fdinfo_entry *fe, struct file_desc *d)
{
	struct pipe_info *pi;

	pi = container_of(d, struct pipe_info, d);
	return !pi->create;
}

static struct file_desc_ops pipe_desc_ops = {
	.type		= FDINFO_PIPE,
	.open		= open_pipe,
	.want_transport	= want_transport,
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

		pi->create = 0;
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

	return collect_pipe_data(CR_FD_PIPES_DATA, pd_hash_pipes);
}

int dump_one_pipe_data(struct pipe_data_dump *pd, int lfd, const struct fd_parms *p)
{
	int img;
	int pipe_size, i, bytes;
	int steal_pipe[2];
	int ret = -1;

	if (p->flags & O_WRONLY)
		return 0;

	/* Maybe we've dumped it already */
	for (i = 0; i < pd->nr; i++) {
		if (pd->ids[i] == p->stat.st_ino)
			return 0;
	}
	
	pr_info("Dumping data from pipe %#x fd %d\n", (u32)p->stat.st_ino, lfd);

	if (pd->nr >= NR_PIPES_WITH_DATA) {
		pr_err("OOM storing pipe\n");
		return -1;
	}

	img = fdset_fd(glob_fdset, pd->img_type);
	pd->ids[pd->nr++] = p->stat.st_ino;

	pipe_size = fcntl(lfd, F_GETPIPE_SZ);
	if (pipe_size < 0) {
		pr_err("Can't obtain piped data size\n");
		goto err;
	}

	if (pipe(steal_pipe) < 0) {
		pr_perror("Can't create pipe for stealing data");
		goto err;
	}

	bytes = tee(lfd, steal_pipe[1], pipe_size, SPLICE_F_NONBLOCK);
	if (bytes > 0) {
		struct pipe_data_entry pde;
		int wrote;

		pde.pipe_id	= p->stat.st_ino;
		pde.bytes	= bytes;
		pde.off		= 0;

		if (bytes > PIPE_MAX_NONALIG_SIZE) {
			off_t off;

			off  = lseek(img, 0, SEEK_CUR);
			off += sizeof(pde);
			off &= ~PAGE_MASK;

			if (off)
				pde.off = PAGE_SIZE - off;

			pr_info("\toff %#lx %#x bytes %#x\n", off, pde.off, bytes);
		}

		if (write_img(img, &pde))
			goto err_close;

		/* Don't forget to advance position if a hole needed */
		if (pde.off)
			lseek(img, pde.off, SEEK_CUR);

		wrote = splice(steal_pipe[0], NULL, img, NULL, bytes, 0);
		if (wrote < 0) {
			pr_perror("Can't push pipe data");
			goto err_close;
		} else if (wrote != bytes) {
			pr_err("%#x: Wanted to write %d bytes, but wrote %d\n",
					(u32)p->stat.st_ino, bytes, wrote);
			goto err_close;
		}
	} else if (bytes < 0) {
		if (errno != EAGAIN) {
			pr_perror("Can't pick pipe data");
			goto err_close;
		}
	}

	ret = 0;

err_close:
	close(steal_pipe[0]);
	close(steal_pipe[1]);
err:
	return ret;
}

static struct pipe_data_dump pd_pipes = { .img_type = CR_FD_PIPES_DATA, };

static int dump_one_pipe(int lfd, u32 id, const struct fd_parms *p)
{
	struct pipe_entry pe;

	pr_info("Dumping pipe %d with id %#x pipe_id %#x\n",
			lfd, id, (u32)p->stat.st_ino);

	pe.id		= id;
	pe.pipe_id	= p->stat.st_ino;
	pe.flags	= p->flags;
	pe.fown		= p->fown;

	if (write_img(fdset_fd(glob_fdset, CR_FD_PIPES), &pe))
		return -1;

	return dump_one_pipe_data(&pd_pipes, lfd, p);
}

static const struct fdtype_ops pipe_ops = {
	.type		= FDINFO_PIPE,
	.make_gen_id	= make_gen_id,
	.dump		= dump_one_pipe,
};

int dump_pipe(struct fd_parms *p, int lfd, const struct cr_fdset *cr_fdset)
{
	return do_dump_gen_file(p, lfd, &pipe_ops, cr_fdset);
}
