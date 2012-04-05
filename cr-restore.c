#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <limits.h>
#include <unistd.h>
#include <errno.h>
#include <dirent.h>
#include <string.h>

#include <fcntl.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/vfs.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <sys/file.h>
#include <sys/shm.h>

#include <sched.h>

#include <sys/sendfile.h>

#include "compiler.h"
#include "types.h"

#include "image.h"
#include "util.h"
#include "log.h"
#include "syscall.h"
#include "restorer.h"
#include "sockets.h"
#include "lock.h"
#include "files.h"
#include "proc_parse.h"
#include "restorer-blob.h"
#include "crtools.h"
#include "namespaces.h"

/*
 * real_pid member formerly served cases when
 * no fork-with-pid functionality were in kernel,
 * so now it is being kept here just in case if
 * we need it again.
 */

#define PIPE_NONE	(0 << 0)
#define PIPE_RDONLY	(1 << 1)
#define PIPE_WRONLY	(1 << 2)
#define PIPE_RDWR	(PIPE_RDONLY | PIPE_WRONLY)
#define PIPE_MODE_MASK	(0x7)
#define PIPE_CREATED	(1 << 3)

#define pipe_is_rw(p)	(((p)->status & PIPE_MODE_MASK) == PIPE_RDWR)

struct pipe_info {
	unsigned int	pipeid;
	int		pid;
	int		read_fd;
	int		write_fd;
	int		status;
	futex_t		real_pid;
	futex_t		users;
};

struct shmem_id {
	struct shmem_id *next;
	unsigned long	addr;
	unsigned long	end;
	unsigned long	shmid;
};

struct pipe_list_entry {
	struct list_head	list;
	struct pipe_entry	e;
	off_t			offset;
};

static struct task_entries *task_entries;

static struct shmem_id *shmem_ids;

static struct shmems *shmems;

static struct pipe_info *pipes;
static int nr_pipes;

static struct pstree_item *me;
static LIST_HEAD(tasks);

static int restore_task_with_children(void *);
static int sigreturn_restore(pid_t pid, struct list_head *vmas, int nr_vmas);

static void show_saved_shmems(void)
{
	int i;

	pr_info("\tSaved shmems:\n");

	for (i = 0; i < shmems->nr_shmems; i++)
		pr_info("\t\tstart: %016lx shmid: %lx pid: %d\n",
			shmems->entries[i].start,
			shmems->entries[i].shmid,
			shmems->entries[i].pid);
}

static void show_saved_pipes(void)
{
	int i;

	pr_info("\tSaved pipes:\n");
	for (i = 0; i < nr_pipes; i++)
		pr_info("\t\tpipeid %x pid %d users %d status %d\n",
			pipes[i].pipeid, pipes[i].pid,
			futex_get(&pipes[i].users), pipes[i].status);
}

static struct pipe_info *find_pipe(unsigned int pipeid)
{
	struct pipe_info *pi;
	int i;

	for (i = 0; i < nr_pipes; i++) {
		pi = pipes + i;
		if (pi->pipeid == pipeid)
			return pi;
	}

	return NULL;
}

static int shmem_wait_and_open(int pid, struct shmem_info *si)
{
	unsigned long time = 1;
	char path[128];
	int ret;

	sprintf(path, "/proc/%d/map_files/%lx-%lx",
		si->pid, si->start, si->end);

	pr_info("%d: Waiting for [%s] to appear\n", pid, path);
	futex_wait_until(&si->lock, 1);

	pr_info("%d: Opening shmem [%s] \n", pid, path);
	ret = open(path, O_RDWR);
	if (ret < 0)
		pr_perror("     %d: Can't stat shmem at %s",
				si->pid, path);
	return ret;
}

static int collect_shmem(int pid, struct vma_entry *vi)
{
	int i;
	struct shmem_info *entries = shmems->entries;
	int nr_shmems = shmems->nr_shmems;
	unsigned long size = vi->pgoff + vi->end - vi->start;
	struct shmem_info *si;

	si = find_shmem(shmems, vi->shmid);
	if (si) {

		if (si->size < size)
			si->size = size;

		/*
		 * Only the shared mapping with a lowest
		 * pid will be created in real, other processes
		 * will wait until the kernel propagate this mapping
		 * into /proc
		 */
		if (si->pid <= pid)
			return 0;

		si->pid	 = pid;
		si->start = vi->start;
		si->end	 = vi->end;

		return 0;
	}

	if ((nr_shmems + 1) * sizeof(struct shmem_info) +
					sizeof (struct shmems) >= SHMEMS_SIZE) {
		pr_err("OOM storing shmems\n");
		return -1;
	}

	pr_info("Add new shmem %lx (0x016%lx-0x016%lx)",
				vi->shmid, vi->start, vi->end);

	si = &shmems->entries[nr_shmems];
	shmems->nr_shmems++;

	si->start = vi->start;
	si->end	  = vi->end;
	si->shmid = vi->shmid;
	si->pid	  = pid;
	si->size  = size;
	si->fd    = -1;

	futex_init(&si->lock);

	return 0;
}

static int prepare_shmem_pid(int pid)
{
	int fd, ret = -1;
	struct vma_entry vi;
	struct task_core_entry tc;
	struct image_header hdr;

	fd = open_image_ro(CR_FD_VMAS, pid);
	if (fd < 0) {
		if (errno == ENOENT)
			return 0;
		else
			return -1;
	}

	while (1) {
		ret = read_img_eof(fd, &vi);
		if (ret <= 0)
			break;

		pr_info("%d: vma %lx %lx\n", pid, vi.start, vi.end);

		if (!vma_entry_is(&vi, VMA_ANON_SHARED))
			continue;

		if (vma_entry_is(&vi, VMA_AREA_SYSVIPC))
			continue;

		ret = collect_shmem(pid, &vi);
		if (ret)
			break;
	}

out:
	close(fd);
	return ret;
}


static int collect_pipe(int pid, struct pipe_entry *e, int p_fd)
{
	int i;

	/*
	 * All pipes get collected into the one array,
	 * note the highest PID is the sign of which
	 * process pipe should be really created, all other
	 * processes (if they have pipes with pipeid matched)
	 * will be attached.
	 */
	for (i = 0; i < nr_pipes; i++) {
		if (pipes[i].pipeid != e->pipeid)
			continue;

		if (pipes[i].pid > pid && !pipe_is_rw(&pipes[i])) {
			pipes[i].pid = pid;
			pipes[i].status = 0;
			pipes[i].read_fd = -1;
			pipes[i].write_fd = -1;
		}

		if (pipes[i].pid == pid) {
			switch (e->flags & O_ACCMODE) {
			case O_RDONLY:
				pipes[i].status |= PIPE_RDONLY;
				pipes[i].read_fd = e->fd;
				break;
			case O_WRONLY:
				pipes[i].status |= PIPE_WRONLY;
				pipes[i].write_fd = e->fd;
				break;
			}
		} else
			futex_inc(&pipes[i].users);

		return 0;
	}

	if ((nr_pipes + 1) * sizeof(struct pipe_info) >= 4096) {
		pr_err("OOM storing pipes\n");
		return -1;
	}

	memset(&pipes[nr_pipes], 0, sizeof(pipes[nr_pipes]));

	pipes[nr_pipes].pipeid	= e->pipeid;
	pipes[nr_pipes].pid	= pid;
	pipes[nr_pipes].read_fd = -1;
	pipes[nr_pipes].write_fd = -1;

	futex_init(&pipes[nr_pipes].users);

	switch (e->flags & O_ACCMODE) {
	case O_RDONLY:
		pipes[nr_pipes].status = PIPE_RDONLY;
		pipes[i].read_fd = e->fd;
		break;
	case O_WRONLY:
		pipes[nr_pipes].status = PIPE_WRONLY;
		pipes[i].write_fd = e->fd;
		break;
	}

	nr_pipes++;

	return 0;
}

static int prepare_pipes_pid(int pid)
{
	int p_fd, ret = 0;

	p_fd = open_image_ro(CR_FD_PIPES, pid);
	if (p_fd < 0) {
		if (errno == ENOENT)
			return 0;
		else
			return -1;
	}

	while (1) {
		struct pipe_entry e;

		ret = read_img_eof(p_fd, &e);
		if (ret <= 0)
			break;

		ret = collect_pipe(pid, &e, p_fd);
		if (ret < 0)
			break;

		if (e.bytes)
			lseek(p_fd, e.bytes, SEEK_CUR);
	}

	close(p_fd);
	return ret;
}

static int shmem_remap(void *old_addr, void *new_addr, unsigned long size)
{
	void *ret;

	ret = mremap(old_addr, size, size,
			MREMAP_FIXED | MREMAP_MAYMOVE, new_addr);
	if (new_addr != ret) {
		pr_perror("mremap failed");
		return -1;
	}

	return 0;
}

static int prepare_pstree(void)
{
	int ret = 0, ps_fd;

	pr_info("Reading image tree\n");

	task_entries = mmap(NULL, TASK_ENTRIES_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANON, 0, 0);
	if (task_entries == MAP_FAILED) {
		pr_perror("Can't map shmem");
		return -1;
	}
	task_entries->nr = 0;
	futex_set(&task_entries->start, CR_STATE_RESTORE);

	ps_fd = open_image_ro(CR_FD_PSTREE);
	if (ps_fd < 0)
		return ps_fd;

	while (1) {
		struct pstree_entry e;
		struct pstree_item *pi;

		ret = read_img_eof(ps_fd, &e);
		if (ret <= 0)
			break;

		ret = -1;
		pi = xmalloc(sizeof(*pi));
		if (pi == NULL)
			break;

		pi->pid = e.pid;

		ret = -1;
		pi->nr_children = e.nr_children;
		pi->children = xmalloc(e.nr_children * sizeof(u32));
		if (!pi->children)
			break;

		ret = read_img_buf(ps_fd, pi->children,
				e.nr_children * sizeof(u32));
		if (ret < 0)
			break;

		ret = -1;
		pi->nr_threads = e.nr_threads;
		pi->threads = xmalloc(e.nr_threads * sizeof(u32));
		if (!pi->threads)
			break;

		ret = read_img_buf(ps_fd, pi->threads,
				e.nr_threads * sizeof(u32));
		if (ret < 0)
			break;

		list_add_tail(&pi->list, &tasks);
		task_entries->nr += e.nr_threads;
	}

	if (!ret)
		futex_set(&task_entries->nr_in_progress, task_entries->nr);

	close(ps_fd);
	return ret;
}

static int prepare_shared(void)
{
	int ret = 0;
	struct pstree_item *pi;

	pr_info("Preparing info about shared resources\n");

	shmems = mmap(NULL, SHMEMS_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANON, 0, 0);
	if (shmems == MAP_FAILED) {
		pr_perror("Can't map shmem");
		return -1;
	}

	shmems->nr_shmems = 0;

	pipes = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANON, 0, 0);
	if (pipes == MAP_FAILED) {
		pr_perror("Can't map pipes");
		return -1;
	}

	if (prepare_shared_fdinfo())
		return -1;

	if (collect_reg_files())
		return -1;

	if (collect_inet_sockets())
		return -1;

	list_for_each_entry(pi, &tasks, list) {
		ret = collect_unix_sockets(pi->pid);
		if (ret < 0)
			return -1;

		ret = prepare_shmem_pid(pi->pid);
		if (ret < 0)
			break;

		ret = prepare_pipes_pid(pi->pid);
		if (ret < 0)
			break;

		ret = prepare_fd_pid(pi->pid);
		if (ret < 0)
			break;
	}

	if (!ret) {
		show_saved_shmems();
		show_saved_pipes();
		show_saved_files();
	}

	return ret;
}

static int restore_shmem_content(void *addr, struct shmem_info *si)
{
	u64 offset;
	int fd, ret = 0;

	fd = open_image_ro(CR_FD_SHMEM_PAGES, si->shmid);
	if (fd < 0) {
		munmap(addr,  si->size);
		return -1;
	}

	while (1) {
		ret = read_img_buf_eof(fd, &offset, sizeof(offset));
		if (ret <= 0)
			break;

		if (offset + PAGE_SIZE > si->size)
			break;

		ret = read_img_buf(fd, addr + offset, PAGE_SIZE);
		if (ret < 0)
			break;
	}

	close(fd);
	return ret;
}

static int get_shmem_fd(int pid, struct vma_entry *vi)
{
	struct shmem_info *si;
	struct shmem_id *shmid;
	int sh_fd;
	void *addr;
	int f;

	si = find_shmem(shmems, vi->shmid);
	pr_info("%d: Search for %016lx shmem %lx %p/%d\n", pid, vi->start, vi->shmid, si, si ? si->pid : -1);
	if (!si) {
		pr_err("Can't find my shmem %016lx\n", vi->start);
		return -1;
	}

	if (si->pid != pid)
		return shmem_wait_and_open(pid, si);

	if (si->fd != -1)
		return dup(si->fd);

	/* The following hack solves problems:
	 * vi->pgoff may be not zero in a target process.
	 * This mapping may be mapped more then once.
	 * The restorer doesn't have snprintf.
	 * Here is a good place to restore content
	 */
	addr = mmap(NULL, si->size,
			PROT_WRITE | PROT_READ,
			MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (addr == MAP_FAILED) {
		pr_err("Can't mmap shmid=0x%lx size=%ld\n",
				vi->shmid, si->size);
		return -1;
	}

	if (restore_shmem_content(addr, si) < 0) {
		pr_err("Can't restore shmem content\n");
		return -1;
	}

	f = open_proc_rw(getpid(), "map_files/%lx-%lx",
			(unsigned long) addr,
			(unsigned long) addr + si->size);
	munmap(addr, si->size);
	if (f < 0)
		return -1;

	si->fd = f;
	return f;
}

static int read_and_open_vmas(int pid, struct list_head *vmas, int *nr_vmas)
{
	int fd, ret = -1;

	fd = open_image_ro(CR_FD_VMAS, pid);
	if (fd < 0)
		return fd;

	*nr_vmas = 0;
	while (1) {
		struct vma_area *vma;

		ret = -1;
		vma = alloc_vma_area();
		if (!vma)
			break;

		(*nr_vmas)++;
		list_add_tail(&vma->list, vmas);
		ret = read_img_eof(fd, &vma->vma);
		if (ret <= 0)
			break;

		if (!(vma_entry_is(&vma->vma, VMA_AREA_REGULAR)))
			continue;

		pr_info("%d: Opening %016lx-%016lx %016lx vma\n",
				pid, vma->vma.start, vma->vma.end, vma->vma.pgoff);

		if (vma_entry_is(&vma->vma, VMA_AREA_SYSVIPC))
			ret = vma->vma.shmid;
		else if (vma_entry_is(&vma->vma, VMA_ANON_SHARED))
			ret = get_shmem_fd(pid, &vma->vma);
		else if (vma_entry_is(&vma->vma, VMA_FILE_PRIVATE) ||
				vma_entry_is(&vma->vma, VMA_FILE_SHARED))
			ret = get_filemap_fd(pid, &vma->vma);
		else
			continue;

		if (ret < 0) {
			pr_err("Can't fixup fd\n");
			break;
		}

		vma->vma.fd = ret;
	}

	close(fd);
	return ret;
}

static int prepare_and_sigreturn(int pid)
{
	int err, nr_vmas;
	LIST_HEAD(vma_list);

	err = read_and_open_vmas(pid, &vma_list, &nr_vmas);
	if (err)
		return err;

	return sigreturn_restore(pid, &vma_list, nr_vmas);
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

static int reopen_pipe(int src, int *dst, int *other, int *pipes_fd)
{
	int tmp;

	if (*dst != -1) {
		if (move_img_fd(other, *dst))
			return -1;

		if (move_img_fd(pipes_fd, *dst))
			return -1;

		return reopen_fd_as(*dst, src);
	}

	*dst = src;
	return 0;
}

static int restore_pipe_data(struct pipe_entry *e, int wfd, int pipes_fd)
{
	int ret, size = 0;

	pr_info("\t%x: Splicing data to %d\n", e->pipeid, wfd);

	while (size != e->bytes) {
		ret = splice(pipes_fd, NULL, wfd, NULL, e->bytes - size, 0);
		if (ret < 0) {
			pr_perror("\t%x: Error splicing data", e->pipeid);
			return -1;
		}
		if (ret == 0) {
			pr_err("\t%x: Wanted to restore %d bytes, but got %d\n",
			       e->pipeid, e->bytes, size);
			return -1;
		}

		size += ret;
	}

	return 0;
}

static int create_pipe(int pid, struct pipe_entry *e, struct pipe_info *pi, int *pipes_fd)
{
	unsigned long time = 1000;
	int pfd[2], tmp;

	pr_info("\t%d: Creating pipe %x%s\n", pid, e->pipeid, pipe_is_rw(pi) ? "(rw)" : "");

	if (pipe(pfd) < 0) {
		pr_perror("%d: Can't create pipe", pid);
		return -1;
	}

	if (restore_pipe_data(e, pfd[1], *pipes_fd))
		return -1;

	if (reopen_pipe(pfd[0], &pi->read_fd, &pfd[1], pipes_fd))
		return -1;
	if (reopen_pipe(pfd[1], &pi->write_fd, &pi->read_fd, pipes_fd))
		return -1;

	futex_set_and_wake(&pi->real_pid, pid);

	pi->status |= PIPE_CREATED;

	pr_info("\t%d: Done, waiting for others (users %d) on %d pid with r:%d w:%d\n",
		pid, futex_get(&pi->users), futex_get(&pi->real_pid), pi->read_fd, pi->write_fd);

	if (!pipe_is_rw(pi)) {
		pr_info("\t%d: Waiting for %x pipe to attach (%d users left)\n",
				pid, e->pipeid, futex_get(&pi->users));

		futex_wait_until(&pi->users, 0);

		if ((e->flags & O_ACCMODE) == O_WRONLY)
			close_safe(&pi->read_fd);
		else
			close_safe(&pi->write_fd);
	}

	tmp = 0;
	if (pi->write_fd != e->fd && pi->read_fd != e->fd) {
		if (move_img_fd(pipes_fd, e->fd))
			return -1;

		switch (e->flags & O_ACCMODE) {
		case O_WRONLY:
			tmp = dup2(pi->write_fd, e->fd);
			break;
		case O_RDONLY:
			tmp = dup2(pi->read_fd, e->fd);
			break;
		}
	}
	if (tmp < 0)
		return -1;

	tmp = set_fd_flags(e->fd, e->flags);
	if (tmp < 0)
		return -1;

	pr_info("\t%d: All is ok - reopening pipe for %d\n", pid, e->fd);

	return 0;
}

static int attach_pipe(int pid, struct pipe_entry *e, struct pipe_info *pi, int *pipes_fd)
{
	char path[128];
	int tmp, fd;

	pr_info("\t%d: Waiting for pipe %x to appear\n",
		pid, e->pipeid);

	futex_wait_while(&pi->real_pid, 0);

	if (move_img_fd(pipes_fd, e->fd))
			return -1;

	if ((e->flags & O_ACCMODE) == O_WRONLY)
		tmp = pi->write_fd;
	else
		tmp = pi->read_fd;

	if (pid == pi->pid) {
		if (tmp != e->fd)
			tmp = dup2(tmp, e->fd);

		if (tmp < 0) {
			pr_perror("%d: Can't duplicate %d->%d",
					pid, tmp, e->fd);
			return -1;
		}

		goto out;
	}

	sprintf(path, "/proc/%d/fd/%d", futex_get(&pi->real_pid), tmp);
	pr_info("\t%d: Attaching pipe %s (%d users left)\n",
		pid, path, futex_get(&pi->users) - 1);

	fd = open(path, e->flags);
	if (fd < 0) {
		pr_perror("%d: Can't attach pipe", pid);
		return -1;
	}

	pr_info("\t%d: Done, reopening for %d\n", pid, e->fd);
	if (reopen_fd_as(e->fd, fd))
		return -1;

	futex_dec_and_wake(&pi->users);
out:
	tmp = set_fd_flags(e->fd, e->flags);
	if (tmp < 0)
		return -1;

	return 0;

}

static int open_pipe(int pid, struct pipe_entry *e, int *pipes_fd)
{
	struct pipe_info *pi;

	pr_info("\t%d: Opening pipe %x on fd %d\n", pid, e->pipeid, e->fd);

	pi = find_pipe(e->pipeid);
	if (!pi) {
		pr_err("BUG: can't find my pipe %x\n", e->pipeid);
		return -1;
	}

	/*
	 * This is somewhat tricky -- in case if a process uses
	 * both pipe ends the pipe should be created but only one
	 * pipe end get connected immediately in create_pipe the
	 * other pipe end should be connected via pipe attaching.
	 */
	if (pi->pid == pid && !(pi->status & PIPE_CREATED))
		return create_pipe(pid, e, pi, pipes_fd);
	else
		return attach_pipe(pid, e, pi, pipes_fd);
}

static rt_sigaction_t sigchld_act;
static int prepare_sigactions(int pid)
{
	rt_sigaction_t act, oact;
	int fd_sigact;
	struct sa_entry e;
	int sig, i;
	int ret = -1;

	fd_sigact = open_image_ro(CR_FD_SIGACT, pid);
	if (fd_sigact < 0)
		return -1;

	for (sig = 1; sig < SIGMAX; sig++) {
		if (sig == SIGKILL || sig == SIGSTOP)
			continue;

		ret = read_img(fd_sigact, &e);
		if (ret < 0)
			break;

		ASSIGN_TYPED(act.rt_sa_handler, e.sigaction);
		ASSIGN_TYPED(act.rt_sa_flags, e.flags);
		ASSIGN_TYPED(act.rt_sa_restorer, e.restorer);
		ASSIGN_TYPED(act.rt_sa_mask.sig[0], e.mask);

		if (sig == SIGCHLD) {
			sigchld_act = act;
			continue;
		}
		/*
		 * A pure syscall is used, because glibc
		 * sigaction overwrites se_restorer.
		 */
		ret = sys_sigaction(sig, &act, &oact);
		if (ret == -1) {
			pr_err("%d: Can't restore sigaction: %m\n", pid);
			goto err;
		}
	}

err:
	close_safe(&fd_sigact);
	return ret;
}

static int prepare_pipes(int pid)
{
	int ret = -1;
	int pipes_fd;

	struct pipe_list_entry *le, *buf;
	int buf_size = PAGE_SIZE;
	int nr = 0;

	LIST_HEAD(head);

	pr_info("%d: Opening pipes\n", pid);

	pipes_fd = open_image_ro(CR_FD_PIPES, pid);
	if (pipes_fd < 0)
		return -1;

	buf = xmalloc(buf_size);
	if (!buf)
		goto out;

	while (1) {
		struct list_head *cur;
		struct pipe_list_entry *cur_entry;

		le = &buf[nr];

		ret = read_img_eof(pipes_fd, &le->e);
		if (ret <= 0)
			break;

		list_for_each(cur, &head) {
			cur_entry = list_entry(cur, struct pipe_list_entry, list);
			if (cur_entry->e.pipeid > le->e.pipeid)
				break;
		}

		list_add_tail(&le->list, cur);

		le->offset = lseek(pipes_fd, 0, SEEK_CUR);
		lseek(pipes_fd, le->e.bytes, SEEK_CUR);

		nr++;
		if (nr > buf_size / sizeof(*le)) {
			ret = -1;
			pr_err("OOM storing pipes");
			break;
		}
	}

	if (!ret)
		list_for_each_entry(le, &head, list) {
			lseek(pipes_fd, le->offset, SEEK_SET);
			if (open_pipe(pid, &le->e, &pipes_fd)) {
				ret = -1;
				break;
			}
		}

	free(buf);
out:
	close_safe(&pipes_fd);
	return ret;
}

static int restore_one_alive_task(int pid)
{
	pr_info("%d: Restoring resources\n", pid);

	if (prepare_pipes(pid))
		return -1;

	if (prepare_sockets(pid))
		return -1;

	if (prepare_fds(pid))
		return -1;

	if (prepare_sigactions(pid))
		return -1;

	return prepare_and_sigreturn(pid);
}

static void zombie_prepare_signals(void)
{
	sigset_t blockmask;
	int sig;
	struct sigaction act;

	sigfillset(&blockmask);
	sigprocmask(SIG_UNBLOCK, &blockmask, NULL);

	memset(&act, 0, sizeof(act));
	act.sa_handler = SIG_DFL;

	for (sig = 1; sig < SIGMAX; sig++)
		sigaction(sig, &act, NULL);
}

#define SIG_FATAL_MASK	(	\
		(1 << SIGHUP)	|\
		(1 << SIGINT)	|\
		(1 << SIGQUIT)	|\
		(1 << SIGILL)	|\
		(1 << SIGTRAP)	|\
		(1 << SIGABRT)	|\
		(1 << SIGIOT)	|\
		(1 << SIGBUS)	|\
		(1 << SIGFPE)	|\
		(1 << SIGKILL)	|\
		(1 << SIGUSR1)	|\
		(1 << SIGSEGV)	|\
		(1 << SIGUSR2)	|\
		(1 << SIGPIPE)	|\
		(1 << SIGALRM)	|\
		(1 << SIGTERM)	|\
		(1 << SIGXCPU)	|\
		(1 << SIGXFSZ)	|\
		(1 << SIGVTALRM)|\
		(1 << SIGPROF)	|\
		(1 << SIGPOLL)	|\
		(1 << SIGIO)	|\
		(1 << SIGSYS)	|\
		(1 << SIGUNUSED)|\
		(1 << SIGSTKFLT)|\
		(1 << SIGPWR)	 \
	)

static inline int sig_fatal(int sig)
{
	return (sig > 0) && (sig < SIGMAX) && (SIG_FATAL_MASK & (1 << sig));
}

static int restore_one_zombie(int pid, int exit_code)
{
	pr_info("Restoring zombie with %d code\n", exit_code);

	if (task_entries != NULL) {
		futex_dec_and_wake(&task_entries->nr_in_progress);
		futex_wait_while(&task_entries->start, CR_STATE_RESTORE);

		zombie_prepare_signals();

		futex_dec_and_wake(&task_entries->nr_in_progress);
		futex_wait_while(&task_entries->start, CR_STATE_RESTORE_SIGCHLD);
	}

	if (exit_code & 0x7f) {
		int signr;

		signr = exit_code & 0x7F;
		if (!sig_fatal(signr)) {
			pr_warn("Exit with non fatal signal ignored\n");
			signr = SIGABRT;
		}

		if (kill(pid, signr) < 0)
			pr_perror("Can't kill myself, will just exit");

		exit_code = 0;
	}

	exit((exit_code >> 8) & 0x7f);

	/* never reached */
	BUG_ON(1);
	return -1;
}

static int check_core_header(int pid, struct task_core_entry *tc)
{
	int fd = -1, ret = -1;
	struct image_header hdr;

	fd = open_image_ro(CR_FD_CORE, pid);
	if (fd < 0)
		return -1;

	if (read_img(fd, &hdr) < 0)
		goto out;

	if (hdr.version != HEADER_VERSION) {
		pr_err("Core version mismatch %d\n", (int)hdr.version);
		goto out;
	}

	if (hdr.arch != HEADER_ARCH_X86_64) {
		pr_err("Core arch mismatch %d\n", (int)hdr.arch);
		goto out;
	}

	ret = read_img(fd, tc);
out:
	close_safe(&fd);
	return ret < 0 ? ret : 0;
}

static int restore_one_task(int pid)
{
	struct task_core_entry tc;

	if (check_core_header(pid, &tc))
		return -1;

	switch ((int)tc.task_state) {
	case TASK_ALIVE:
		return restore_one_alive_task(pid);
	case TASK_DEAD:
		return restore_one_zombie(pid, tc.exit_code);
	default:
		pr_err("Unknown state in code %d\n", (int)tc.task_state);
		return -1;
	}
}

/*
 * This stack size is important for the restorer
 * itself only. At the final phase, we will switch
 * to the original stack the program had at checkpoint
 * time.
 */
#define STACK_SIZE	(8 * 4096)
struct cr_clone_arg {
	int pid, fd;
	unsigned long clone_flags;
};

static inline int fork_with_pid(int pid, unsigned long ns_clone_flags)
{
	int ret = -1;
	char buf[32];
	struct cr_clone_arg ca;
	void *stack;

	pr_info("Forking task with %d pid (flags %lx)\n", pid, ns_clone_flags);

	stack = mmap(NULL, STACK_SIZE, PROT_WRITE | PROT_READ,
			MAP_PRIVATE | MAP_GROWSDOWN | MAP_ANONYMOUS, -1, 0);
	if (stack == MAP_FAILED) {
		pr_perror("Failed to map stack for the child");
		goto err;
	}

	snprintf(buf, sizeof(buf), "%d", pid - 1);
	ca.pid = pid;
	ca.clone_flags = ns_clone_flags;
	ca.fd = open(LAST_PID_PATH, O_RDWR);
	if (ca.fd < 0) {
		pr_perror("%d: Can't open %s", pid, LAST_PID_PATH);
		goto err;
	}

	if (flock(ca.fd, LOCK_EX)) {
		pr_perror("%d: Can't lock %s", pid, LAST_PID_PATH);
		goto err_close;
	}

	if (write_img_buf(ca.fd, buf, strlen(buf)))
		goto err_unlock;

	ret = clone(restore_task_with_children, stack + STACK_SIZE,
			ns_clone_flags | SIGCHLD, &ca);

	if (ret < 0)
		pr_perror("Can't fork for %d", pid);

err_unlock:
	if (flock(ca.fd, LOCK_UN))
		pr_perror("%d: Can't unlock %s", pid, LAST_PID_PATH);

err_close:
	close_safe(&ca.fd);
err:
	if (stack != MAP_FAILED)
		munmap(stack, STACK_SIZE);
	return ret;
}

static void sigchld_handler(int signal, siginfo_t *siginfo, void *data)
{
	int status, pid;

	if (siginfo->si_code & CLD_EXITED)
		pr_err("%d exited, status=%d\n",
			siginfo->si_pid, siginfo->si_status);
	else if (siginfo->si_code & CLD_KILLED)
		pr_err("%d killed by signal %d\n",
			siginfo->si_pid, siginfo->si_status);

	futex_abort_and_wake(&task_entries->nr_in_progress);
}

static int restore_task_with_children(void *_arg)
{
	struct cr_clone_arg *ca = _arg;
	pid_t pid;
	int ret, i;
	sigset_t blockmask;

	close_safe(&ca->fd);

	pid = getpid();
	if (ca->pid != pid) {
		pr_err("%d: Pid do not match expected %d\n", me->pid, ca->pid);
		exit(-1);
	}

	list_for_each_entry(me, &tasks, list)
		if (me->pid == pid)
			break;

	if (me == list_entry(&tasks, struct pstree_item, list)) {
		pr_err("Pid %d not found in pstree image\n", pid);
		exit(1);
	}

	if (ca->clone_flags) {
		ret = prepare_namespace(me->pid, ca->clone_flags);
		if (ret)
			exit(-1);
	}

	/*
	 * The block mask will be restored in sigresturn.
	 *
	 * TODO: This code should be removed, when a freezer will be added.
	 */
	sigfillset(&blockmask);
	sigdelset(&blockmask, SIGCHLD);
	ret = sigprocmask(SIG_BLOCK, &blockmask, NULL);
	if (ret) {
		pr_perror("%d: Can't block signals", me->pid);
		exit(1);
	}

	pr_info("%d: Restoring %d children:\n", me->pid, me->nr_children);
	for (i = 0; i < me->nr_children; i++) {
		ret = fork_with_pid(me->children[i], 0);
		if (ret < 0)
			exit(1);
	}

	return restore_one_task(me->pid);
}

static int restore_root_task(pid_t pid, struct cr_options *opts)
{
	int ret, i;
	struct sigaction act, old_act;
	struct pstree_item *init;

	ret = sigaction(SIGCHLD, NULL, &act);
	if (ret < 0) {
		perror("sigaction() failed\n");
		return -1;
	}

	act.sa_flags |= SA_NOCLDWAIT | SA_NOCLDSTOP | SA_SIGINFO | SA_RESTART;
	act.sa_sigaction = sigchld_handler;
	ret = sigaction(SIGCHLD, &act, &old_act);
	if (ret < 0) {
		perror("sigaction() failed\n");
		return -1;
	}

	init = list_first_entry(&tasks, struct pstree_item, list);
	if (init->pid != pid) {
		pr_err("Pids mismatch. Init has pid %d, requested %d\n",
				init->pid, pid);
		return -1;
	}

	/*
	 * FIXME -- currently we assume that all the tasks live
	 * in the same set of namespaces. This is done to debug
	 * the ns contents dumping/restoring. Need to revisit
	 * this later.
	 */

	ret = fork_with_pid(init->pid, opts->namespaces_flags);
	if (ret < 0)
		return -1;

	pr_info("Wait until all tasks are restored\n");
	futex_wait_while_gt(&task_entries->nr_in_progress, 0);
	ret = (int)futex_get(&task_entries->nr_in_progress);

out:
	if (ret < 0) {
		pr_err("Someone can't be restored\n");
		struct pstree_item *pi;

		list_for_each_entry(pi, &tasks, list)
			kill(pi->pid, SIGKILL);
		return 1;
	}

	futex_set_and_wake(&task_entries->nr_in_progress, task_entries->nr);
	futex_set_and_wake(&task_entries->start, CR_STATE_RESTORE_SIGCHLD);
	futex_wait_until(&task_entries->nr_in_progress, 0);

	ret = sigaction(SIGCHLD, &old_act, NULL);
	if (ret < 0) {
		perror("sigaction() failed\n");
		return -1;
	}

	pr_info("Go on!!!\n");
	futex_set_and_wake(&task_entries->start, CR_STATE_COMPLETE);

	if (!opts->restore_detach)
		wait(NULL);
	return 0;
}

static int restore_all_tasks(pid_t pid, struct cr_options *opts)
{
	if (prepare_pstree() < 0)
		return -1;

	if (prepare_shared() < 0)
		return -1;

	return restore_root_task(pid, opts);
}

static long restorer_get_vma_hint(pid_t pid, struct list_head *tgt_vma_list,
		struct list_head *self_vma_list, long vma_len)
{
	struct vma_area *t_vma;
	long prev_vma_end = 0;

	/*
	 * Here we need some heuristics -- the VMA which restorer will
	 * belong to should not be unmapped, so we need to gueess out
	 * where to put it in.
	 *
	 * Yes, I know it's an O(n^2) algorithm, but usually there are
	 * not that many VMAs presented so instead of consuming memory
	 * better to stick with it.
	 */

	list_for_each_entry(t_vma, tgt_vma_list, list) {
		if (prev_vma_end && ((t_vma->vma.start - prev_vma_end) > vma_len)) {
			struct vma_area *s_vma;
			unsigned long prev_vma_end2 = 0;

			list_for_each_entry(s_vma, self_vma_list, list) {
				if (prev_vma_end2 && (prev_vma_end2 >= prev_vma_end) &&
				    ((s_vma->vma.start - prev_vma_end2) > vma_len))
					return prev_vma_end2;

				prev_vma_end2 = s_vma->vma.end;
			}
		}

		prev_vma_end = t_vma->vma.end;
	}

	return -1;
}

#define USEC_PER_SEC	1000000L

static inline int timeval_valid(struct timeval *tv)
{
	return (tv->tv_sec >= 0) && ((unsigned long)tv->tv_usec < USEC_PER_SEC);
}

static inline int itimer_restore_and_fix(char *n, struct itimer_entry *ie,
		struct itimerval *val)
{
	if (ie->isec == 0 && ie->iusec == 0) {
		memzero_p(val);
		return 0;
	}

	val->it_interval.tv_sec = ie->isec;
	val->it_interval.tv_usec = ie->iusec;

	if (!timeval_valid(&val->it_interval)) {
		pr_err("Invalid timer interval\n");
		return -1;
	}

	if (ie->vsec == 0 && ie->vusec == 0) {
		/*
		 * Remaining time was too short. Set it to
		 * interval to make the timer armed and work.
		 */
		val->it_value.tv_sec = ie->isec;
		val->it_value.tv_usec = ie->iusec;
	} else {
		val->it_value.tv_sec = ie->vsec;
		val->it_value.tv_usec = ie->vusec;
	}

	if (!timeval_valid(&val->it_value)) {
		pr_err("Invalid timer value\n");
		return -1;
	}

	pr_info("Restored %s timer to %ld.%ld -> %ld.%ld\n", n,
			val->it_value.tv_sec, val->it_value.tv_usec,
			val->it_interval.tv_sec, val->it_interval.tv_usec);

	return 0;
}

static int prepare_itimers(int pid, struct task_restore_core_args *args)
{
	int fd, ret = -1;
	struct itimer_entry ie[3];

	fd = open_image_ro(CR_FD_ITIMERS, pid);
	if (fd < 0)
		return fd;

	if (read_img_buf(fd, ie, sizeof(ie)) > 0) {
		ret = itimer_restore_and_fix("real",
				&ie[0], &args->itimers[0]);
		if (!ret)
			ret = itimer_restore_and_fix("virt",
					&ie[1], &args->itimers[1]);
		if (!ret)
			ret = itimer_restore_and_fix("prof",
					&ie[2], &args->itimers[2]);
	}

	close_safe(&fd);
	return ret;
}

static int prepare_creds(int pid, struct task_restore_core_args *args)
{
	int fd, ret;

	fd = open_image_ro(CR_FD_CREDS, pid);
	if (fd < 0)
		return fd;

	ret = read_img(fd, &args->creds);

	close_safe(&fd);

	/* XXX -- validate creds here? */

	return ret > 0 ? 0 : -1;
}

static struct vma_entry *vma_list_remap(void *addr, unsigned long len, struct list_head *vmas)
{
	struct vma_entry *vma, *ret;
	struct vma_area *vma_area;

	ret = vma = mmap(addr, len, PROT_READ | PROT_WRITE,
			MAP_PRIVATE | MAP_ANON | MAP_FIXED, 0, 0);
	if (vma != addr) {
		pr_perror("Can't remap vma area");
		return NULL;
	}

	list_for_each_entry(vma_area, vmas, list) {
		*vma = vma_area->vma;
		vma++;
	}

	vma->start = 0;
	free_mappings(vmas);

	return ret;
}

static int sigreturn_restore(pid_t pid, struct list_head *tgt_vmas, int nr_vmas)
{
	long restore_code_len, restore_task_vma_len;
	long restore_thread_vma_len, self_vmas_len, vmas_len;

	void *mem = MAP_FAILED;
	void *restore_thread_exec_start;
	void *restore_task_exec_start;
	void *restore_code_start;

	long new_sp, exec_mem_hint;
	long ret;

	struct task_restore_core_args *task_args;
	struct thread_restore_args *thread_args;

	LIST_HEAD(self_vma_list);
	int fd_core = -1;
	int fd_pages = -1;
	int i;

	int *fd_core_threads;

	pr_info("%d: Restore via sigreturn\n", pid);

	restore_code_len	= 0;
	restore_task_vma_len	= 0;
	restore_thread_vma_len	= 0;

	ret = parse_maps(pid, &self_vma_list, false);
	close_pid_proc();
	if (ret < 0)
		goto err;

	self_vmas_len = round_up((ret + 1) * sizeof(struct vma_entry), PAGE_SIZE);
	vmas_len = round_up((nr_vmas + 1) * sizeof(struct vma_entry), PAGE_SIZE);

	/* pr_info_vma_list(&self_vma_list); */

	BUILD_BUG_ON(sizeof(struct task_restore_core_args) & 1);
	BUILD_BUG_ON(sizeof(struct thread_restore_args) & 1);
	BUILD_BUG_ON(SHMEMS_SIZE % PAGE_SIZE);
	BUILD_BUG_ON(TASK_ENTRIES_SIZE % PAGE_SIZE);

	fd_core = open_image_ro(CR_FD_CORE, pid);
	if (fd_core < 0) {
		pr_perror("Can't open core-out-%d", pid);
		goto err;
	}

	fd_pages = open_image_ro(CR_FD_PAGES, pid);
	if (fd_pages < 0) {
		pr_perror("Can't open pages-%d", pid);
		goto err;
	}

	restore_code_len	= sizeof(restorer_blob);
	restore_code_len	= round_up(restore_code_len, 16);

	restore_task_vma_len	= round_up(restore_code_len + sizeof(*task_args), PAGE_SIZE);

	/*
	 * Thread statistics
	 */

	/*
	 * Compute how many memory we will need
	 * to restore all threads, every thread
	 * requires own stack and heap, it's ~40K
	 * per thread.
	 */

	restore_thread_vma_len = sizeof(*thread_args) * me->nr_threads;
	restore_thread_vma_len = round_up(restore_thread_vma_len, 16);

	pr_info("%d: %d threads require %ldK of memory\n",
			pid, me->nr_threads,
			KBYTES(restore_thread_vma_len));

	restore_thread_vma_len = round_up(restore_thread_vma_len, PAGE_SIZE);

	exec_mem_hint = restorer_get_vma_hint(pid, tgt_vmas, &self_vma_list,
					      restore_task_vma_len +
					      restore_thread_vma_len +
					      self_vmas_len +
					      SHMEMS_SIZE + TASK_ENTRIES_SIZE);
	if (exec_mem_hint == -1) {
		pr_err("No suitable area for task_restore bootstrap (%ldK)\n",
		       restore_task_vma_len + restore_thread_vma_len);
		goto err;
	}

	pr_info("Found bootstrap VMA hint at: %lx (needs ~%ldK)\n", exec_mem_hint,
			KBYTES(restore_task_vma_len + restore_thread_vma_len));

	/* VMA we need to run task_restore code */
	mem = mmap((void *)exec_mem_hint,
			restore_task_vma_len + restore_thread_vma_len,
			PROT_READ | PROT_WRITE | PROT_EXEC,
			MAP_PRIVATE | MAP_ANON | MAP_FIXED, 0, 0);
	if (mem != (void *)exec_mem_hint) {
		pr_err("Can't mmap section for restore code\n");
		goto err;
	}

	/*
	 * Prepare a memory map for restorer. Note a thread space
	 * might be completely unused so it's here just for convenience.
	 */
	restore_code_start		= mem;
	restore_thread_exec_start	= restore_code_start + restorer_blob_offset__restore_thread;
	restore_task_exec_start		= restore_code_start + restorer_blob_offset__restore_task;
	task_args			= restore_code_start + restore_code_len;
	thread_args			= (void *)((long)task_args + sizeof(*task_args));

	memzero_p(task_args);
	memzero(thread_args, sizeof(*thread_args) * me->nr_threads);

	/*
	 * Code at a new place.
	 */
	memcpy(restore_code_start, &restorer_blob, sizeof(restorer_blob));

	/*
	 * Adjust stack.
	 */
	new_sp = RESTORE_ALIGN_STACK((long)task_args->mem_zone.stack, sizeof(task_args->mem_zone.stack));

	/*
	 * Get a reference to shared memory area which is
	 * used to signal if shmem restoration complete
	 * from low-level restore code.
	 *
	 * This shmem area is mapped right after the whole area of
	 * sigreturn rt code. Note we didn't allocated it before
	 * but this area is taken into account for 'hint' memory
	 * address.
	 */

	mem += restore_task_vma_len + restore_thread_vma_len;
	ret = shmem_remap(shmems, mem, SHMEMS_SIZE);
	if (ret < 0)
		goto err;
	task_args->shmems = mem;

	mem += SHMEMS_SIZE;
	ret = shmem_remap(task_entries, mem, TASK_ENTRIES_SIZE);
	if (ret < 0)
		goto err;
	task_args->task_entries = mem;

	mem += TASK_ENTRIES_SIZE;
	task_args->self_vmas = vma_list_remap(mem, self_vmas_len, &self_vma_list);
	if (!task_args->self_vmas)
		goto err;

	mem += self_vmas_len;
	task_args->tgt_vmas = vma_list_remap(mem, vmas_len, tgt_vmas);
	if (!task_args->tgt_vmas)
		goto err;

	/*
	 * Arguments for task restoration.
	 */
	task_args->pid		= pid;
	task_args->fd_core	= fd_core;
	task_args->logfd	= log_get_fd();
	task_args->sigchld_act	= sigchld_act;
	task_args->fd_exe_link	= self_exe_fd;
	task_args->fd_pages	= fd_pages;

	ret = prepare_itimers(pid, task_args);
	if (ret < 0)
		goto err;

	ret = prepare_creds(pid, task_args);
	if (ret < 0)
		goto err;

	mutex_init(&task_args->rst_lock);

	/*
	 * Now prepare run-time data for threads restore.
	 */
	task_args->nr_threads		= me->nr_threads;
	task_args->clone_restore_fn	= (void *)restore_thread_exec_start;
	task_args->thread_args		= thread_args;

	/*
	 * Fill up per-thread data.
	 */
	for (i = 0; i < me->nr_threads; i++) {
		thread_args[i].pid = me->threads[i];

		/* skip self */
		if (thread_args[i].pid == pid)
			continue;

		/* Core files are to be opened */
		thread_args[i].fd_core = open_image_ro_nocheck(FMT_FNAME_CORE, thread_args[i].pid);
		if (thread_args[i].fd_core < 0)
			goto err;

		thread_args[i].rst_lock = &task_args->rst_lock;

		pr_info("Thread %4d stack %8p heap %8p rt_sigframe %8p\n",
				i, thread_args[i].mem_zone.stack,
				thread_args[i].mem_zone.heap,
				thread_args[i].mem_zone.rt_sigframe);

	}

	close_image_dir();

	pr_info("task_args: %p\n"
		"task_args->pid: %d\n"
		"task_args->fd_core: %d\n"
		"task_args->nr_threads: %d\n"
		"task_args->clone_restore_fn: %p\n"
		"task_args->thread_args: %p\n",
		task_args, task_args->pid,
		task_args->fd_core,
		task_args->nr_threads,
		task_args->clone_restore_fn,
		task_args->thread_args);

	/*
	 * An indirect call to task_restore, note it never resturns
	 * and restoreing core is extremely destructive.
	 */
	asm volatile(
		"movq %0, %%rbx						\n"
		"movq %1, %%rax						\n"
		"movq %2, %%rdi						\n"
		"movq %%rbx, %%rsp					\n"
		"callq *%%rax						\n"
		:
		: "g"(new_sp),
		  "g"(restore_task_exec_start),
		  "g"(task_args)
		: "rsp", "rdi", "rsi", "rbx", "rax", "memory");

err:
	free_mappings(&self_vma_list);
	close_safe(&fd_core);

	/* Just to be sure */
	exit(1);
	return -1;
}

int cr_restore_tasks(pid_t pid, struct cr_options *opts)
{
	if (opts->leader_only)
		return restore_one_task(pid);
	return restore_all_tasks(pid, opts);
}
