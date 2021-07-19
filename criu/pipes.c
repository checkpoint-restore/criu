#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <sys/mman.h>

#include "crtools.h"
#include "imgset.h"
#include "image.h"
#include "files.h"
#include "pipes.h"
#include "util-pie.h"
#include "autofs.h"

#include "protobuf.h"
#include "util.h"
#include "images/pipe.pb-c.h"
#include "images/pipe-data.pb-c.h"
#include "fcntl.h"
#include "namespaces.h"

static LIST_HEAD(pipes);

static void show_saved_pipe_fds(struct pipe_info *pi)
{
	struct fdinfo_list_entry *fle;

	pr_info("  `- ID %p %#x\n", pi, pi->pe->id);
	list_for_each_entry(fle, &pi->d.fd_info_head, desc_list)
		pr_info("   `- FD %d pid %d\n", fle->fe->fd, fle->pid);
}

static int pipe_data_read(struct cr_img *img, struct pipe_data_rst *r)
{
	unsigned long bytes = r->pde->bytes;

	if (!bytes)
		return 0;

	/*
	 * We potentially allocate more memory than required for data,
	 * but this is OK. Look at restore_pipe_data -- it vmsplice-s
	 * this into the kernel with F_GIFT flag (since some time it
	 * works on non-aligned data), thus just giving this page to
	 * pipe buffer. And since kernel allocates pipe buffers in pages
	 * anyway we don't increase memory consumption :)
	 */

	r->data = mmap(NULL, bytes, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, 0, 0);
	if (r->data == MAP_FAILED) {
		pr_perror("Can't map mem for pipe buffers");
		return -1;
	}

	return read_img_buf(img, r->data, bytes);
}

int do_collect_pipe_data(struct pipe_data_rst *r, ProtobufCMessage *msg, struct cr_img *img,
			 struct pipe_data_rst **hash)
{
	int aux;

	r->pde = pb_msg(msg, PipeDataEntry);
	aux = pipe_data_read(img, r);
	if (aux < 0)
		return aux;

	aux = r->pde->pipe_id & PIPE_DATA_HASH_MASK;
	r->next = hash[aux];
	hash[aux] = r;
	pr_info("Collected pipe data for %#x (chain %u)\n", r->pde->pipe_id, aux);
	return 0;
}

/* Choose who will restore a pipe. */
static int mark_pipe_master_cb(struct pprep_head *ph)
{
	LIST_HEAD(head);

	pr_info("Pipes:\n");

	while (1) {
		struct fdinfo_list_entry *fle;
		struct pipe_info *pi, *pic, *p;
		struct pipe_info *pr = NULL, *pw = NULL;

		if (list_empty(&pipes))
			break;

		pi = list_first_entry(&pipes, struct pipe_info, list);
		list_move(&pi->list, &head);

		pr_info(" `- PIPE ID %#x\n", pi->pe->pipe_id);
		show_saved_pipe_fds(pi);

		fle = file_master(&pi->d);
		p = pi;
		if (!(pi->pe->flags & O_LARGEFILE)) {
			if (pi->pe->flags & O_WRONLY) {
				if (pw == NULL)
					pw = pi;
			} else {
				if (pr == NULL)
					pr = pi;
			}
		}

		list_for_each_entry(pic, &pi->pipe_list, pipe_list) {
			struct fdinfo_list_entry *f;

			list_move(&pic->list, &head);
			f = file_master(&pic->d);
			if (fdinfo_rst_prio(f, fle)) {
				p = pic;
				fle = f;
			}

			if (!(pic->pe->flags & O_LARGEFILE)) {
				if (pic->pe->flags & O_WRONLY) {
					if (pw == NULL)
						pw = pic;
				} else {
					if (pr == NULL)
						pr = pic;
				}
			}

			show_saved_pipe_fds(pic);
		}
		p->create = 1;
		if (pr)
			pr->reopen = 0;
		if (pw)
			pw->reopen = 0;
		pr_info("    by %#x\n", p->pe->id);
	}

	list_splice(&head, &pipes);
	return 0;
}

static MAKE_PPREP_HEAD(mark_pipe_master);

static struct pipe_data_rst *pd_hash_pipes[PIPE_DATA_HASH_SIZE];

int restore_pipe_data(int img_type, int pfd, u32 id, struct pipe_data_rst **hash)
{
	int ret;
	struct pipe_data_rst *pd;
	struct iovec iov;

	for (pd = hash[id & PIPE_DATA_HASH_MASK]; pd != NULL; pd = pd->next)
		if (pd->pde->pipe_id == id)
			break;

	if (!pd) { /* no data for this pipe */
		pr_info("No data for pipe %#x\n", id);
		return 0;
	}

	if (pd->pde->has_size) {
		pr_info("Restoring size %#x for %#x\n", pd->pde->size, pd->pde->pipe_id);
		ret = fcntl(pfd, F_SETPIPE_SZ, pd->pde->size);
		if (ret < 0) {
			pr_perror("Can't restore pipe size");
			return -1;
		}
	}

	if (!pd->pde->bytes)
		return 0;

	if (!pd->data) {
		pr_err("Double data restore occurred on %#x\n", id);
		return -1;
	}

	iov.iov_base = pd->data;
	iov.iov_len = pd->pde->bytes;

	while (iov.iov_len > 0) {
		ret = vmsplice(pfd, &iov, 1, SPLICE_F_GIFT | SPLICE_F_NONBLOCK);
		if (ret < 0) {
			pr_perror("%#x: Error splicing data", id);
			return -1;
		}

		if (ret == 0 || ret > iov.iov_len /* sanity */) {
			pr_err("%#x: Wanted to restore %zu bytes, but got %d\n", id, iov.iov_len, ret);
			return -1;
		}

		iov.iov_base += ret;
		iov.iov_len -= ret;
	}

	/*
	 * 3 reasons for killing the buffer from our address space:
	 *
	 * 1. We gifted the pages to the kernel to optimize memory usage, thus
	 *    accidental memory corruption can change the pipe buffer.
	 * 2. This will make the vmas restoration a bit faster due to less self
	 *    mappings to be unmapped.
	 * 3. We can catch bugs with double pipe data restore.
	 */

	munmap(pd->data, pd->pde->bytes);
	pd->data = NULL;
	return 0;
}

static int userns_reopen(void *_arg, int fd, pid_t pid)
{
	char path[PSFDS];
	int ret, flags = *(int *)_arg;

	sprintf(path, "/proc/self/fd/%d", fd);
	ret = open(path, flags);
	if (ret < 0)
		pr_perror("Unable to reopen the pipe %s", path);
	close(fd);

	return ret;
}

static int reopen_pipe(int fd, int flags)
{
	int ret;
	char path[PSFDS];

	sprintf(path, "/proc/self/fd/%d", fd);
	ret = open(path, flags);
	if (ret < 0) {
		if (errno == EACCES) {
			/* It may be an external pipe from an another userns */
			ret = userns_call(userns_reopen, UNS_FDOUT, &flags, sizeof(flags), fd);
		} else
			pr_perror("Unable to reopen the pipe %s", path);
	}
	close(fd);

	return ret;
}

static int recv_pipe_fd(struct pipe_info *pi, int *new_fd)
{
	int tmp, fd, ret;

	ret = recv_desc_from_peer(&pi->d, &tmp);
	if (ret != 0) {
		if (ret != 1)
			pr_err("Can't get fd %d\n", tmp);
		return ret;
	}

	if (pi->reopen)
		fd = reopen_pipe(tmp, pi->pe->flags);
	else
		fd = tmp;
	if (fd >= 0) {
		if (rst_file_params(fd, pi->pe->fown, pi->pe->flags)) {
			close(fd);
			return -1;
		}
		*new_fd = fd;
	}

	return fd < 0 ? -1 : 0;
}

static char *pipe_d_name(struct file_desc *d, char *buf, size_t s)
{
	struct pipe_info *pi;

	pi = container_of(d, struct pipe_info, d);
	if (snprintf(buf, s, "pipe:[%u]", pi->pe->pipe_id) >= s) {
		pr_err("Not enough room for pipe %u identifier string\n", pi->pe->pipe_id);
		return NULL;
	}

	return buf;
}

int open_pipe(struct file_desc *d, int *new_fd)
{
	struct pipe_info *pi, *p;
	int ret, tmp;
	int pfd[2];

	pi = container_of(d, struct pipe_info, d);
	pr_info("\t\tCreating pipe pipe_id=%#x id=%#x\n", pi->pe->pipe_id, pi->pe->id);
	if (inherited_fd(d, &tmp)) {
		if (tmp < 0)
			return tmp;

		pi->reopen = 1;
		goto reopen;
	}

	if (!pi->create)
		return recv_pipe_fd(pi, new_fd);

	if (pipe(pfd) < 0) {
		pr_perror("Can't create pipe");
		return -1;
	}

	ret = restore_pipe_data(CR_FD_PIPES_DATA, pfd[1], pi->pe->pipe_id, pd_hash_pipes);
	if (ret)
		return -1;

	list_for_each_entry(p, &pi->pipe_list, pipe_list) {
		int fd = pfd[p->pe->flags & O_WRONLY];

		if (send_desc_to_peer(fd, &p->d)) {
			pr_perror("Can't send file descriptor");
			return -1;
		}
	}

	close(pfd[!(pi->pe->flags & O_WRONLY)]);
	tmp = pfd[pi->pe->flags & O_WRONLY];

reopen:
	if (pi->reopen)
		tmp = reopen_pipe(tmp, pi->pe->flags);

	if (tmp >= 0)
		if (rst_file_params(tmp, pi->pe->fown, pi->pe->flags))
			return -1;
	if (tmp < 0)
		return -1;
	*new_fd = tmp;
	return 0;
}

static struct file_desc_ops pipe_desc_ops = {
	.type = FD_TYPES__PIPE,
	.open = open_pipe,
	.name = pipe_d_name,
};

int collect_one_pipe_ops(void *o, ProtobufCMessage *base, struct file_desc_ops *ops)
{
	struct pipe_info *pi = o, *tmp;

	pi->pe = pb_msg(base, PipeEntry);

	pi->create = 0;
	pi->reopen = 1;
	pr_info("Collected pipe entry ID %#x PIPE ID %#x\n", pi->pe->id, pi->pe->pipe_id);

	if (file_desc_add(&pi->d, pi->pe->id, ops))
		return -1;

	INIT_LIST_HEAD(&pi->pipe_list);
	if (!inherited_fd(&pi->d, NULL)) {
		list_for_each_entry(tmp, &pipes, list)
			if (pi->pe->pipe_id == tmp->pe->pipe_id)
				break;

		if (&tmp->list != &pipes)
			list_add(&pi->pipe_list, &tmp->pipe_list);
	}

	add_post_prepare_cb_once(&mark_pipe_master);
	list_add_tail(&pi->list, &pipes);

	return 0;
}

static int collect_one_pipe(void *o, ProtobufCMessage *base, struct cr_img *i)
{
	return collect_one_pipe_ops(o, base, &pipe_desc_ops);
}

struct collect_image_info pipe_cinfo = {
	.fd_type = CR_FD_PIPES,
	.pb_type = PB_PIPE,
	.priv_size = sizeof(struct pipe_info),
	.collect = collect_one_pipe,
};

static int collect_pipe_data(void *obj, ProtobufCMessage *msg, struct cr_img *img)
{
	return do_collect_pipe_data(obj, msg, img, pd_hash_pipes);
}

struct collect_image_info pipe_data_cinfo = {
	.fd_type = CR_FD_PIPES_DATA,
	.pb_type = PB_PIPE_DATA,
	.priv_size = sizeof(struct pipe_data_rst),
	.collect = collect_pipe_data,
};

int dump_one_pipe_data(struct pipe_data_dump *pd, int lfd, const struct fd_parms *p)
{
	struct cr_img *img;
	int pipe_size, i, bytes;
	int steal_pipe[2];
	int ret = -1;
	PipeDataEntry pde = PIPE_DATA_ENTRY__INIT;

	if (p->flags & O_WRONLY)
		return 0;

	/* Maybe we've dumped it already */
	for (i = 0; i < pd->nr; i++) {
		if (pd->ids[i] == pipe_id(p))
			return 0;
	}

	pr_info("Dumping data from pipe %#x fd %d\n", pipe_id(p), lfd);

	if (pd->nr >= NR_PIPES_WITH_DATA) {
		pr_err("OOM storing pipe\n");
		return -1;
	}

	img = img_from_set(glob_imgset, pd->img_type);
	pd->ids[pd->nr++] = pipe_id(p);

	pipe_size = fcntl(lfd, F_GETPIPE_SZ);
	if (pipe_size < 0) {
		pr_err("Can't obtain piped data size\n");
		goto err;
	}

	if (pipe(steal_pipe) < 0) {
		pr_perror("Can't create pipe for stealing data");
		goto err;
	}

	/* steal_pipe has to be able to fit all data from a target pipe */
	if (fcntl(steal_pipe[1], F_SETPIPE_SZ, pipe_size) < 0) {
		pr_perror("Unable to set a pipe size");
		goto err;
	}

	bytes = tee(lfd, steal_pipe[1], pipe_size, SPLICE_F_NONBLOCK);
	if (bytes < 0) {
		if (errno != EAGAIN) {
			pr_perror("Can't pick pipe data");
			goto err_close;
		}

		bytes = 0;
	}

	pde.pipe_id = pipe_id(p);
	pde.bytes = bytes;
	pde.has_size = true;
	pde.size = pipe_size;

	if (pb_write_one(img, &pde, PB_PIPE_DATA))
		goto err_close;

	while (bytes > 0) {
		int wrote;
		wrote = splice(steal_pipe[0], NULL, img_raw_fd(img), NULL, bytes, 0);
		if (wrote < 0) {
			pr_perror("Can't push pipe data");
			goto err_close;
		} else if (wrote == 0)
			break;
		bytes -= wrote;
	}

	ret = 0;

err_close:
	close(steal_pipe[0]);
	close(steal_pipe[1]);
err:
	return ret;
}

static struct pipe_data_dump pd_pipes = {
	.img_type = CR_FD_PIPES_DATA,
};

static int dump_one_pipe(int lfd, u32 id, const struct fd_parms *p)
{
	FileEntry fe = FILE_ENTRY__INIT;
	PipeEntry pe = PIPE_ENTRY__INIT;

	pr_info("Dumping pipe %d with id %#x pipe_id %#x\n", lfd, id, pipe_id(p));

	if ((p->flags & O_DIRECT) && !is_autofs_pipe(pipe_id(p))) {
		pr_err("The packetized mode for pipes is not supported yet\n");
		return -1;
	}

	pe.id = id;
	pe.pipe_id = pipe_id(p);
	pe.flags = p->flags & ~O_DIRECT;
	pe.fown = (FownEntry *)&p->fown;

	fe.type = FD_TYPES__PIPE;
	fe.id = pe.id;
	fe.pipe = &pe;

	if (pb_write_one(img_from_set(glob_imgset, CR_FD_FILES), &fe, PB_FILE))
		return -1;

	return dump_one_pipe_data(&pd_pipes, lfd, p);
}

const struct fdtype_ops pipe_dump_ops = {
	.type = FD_TYPES__PIPE,
	.dump = dump_one_pipe,
};
