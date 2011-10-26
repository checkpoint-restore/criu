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

#include <sched.h>

#include <sys/sendfile.h>

#include "compiler.h"
#include "types.h"

#include "image.h"
#include "util.h"
#include "syscall.h"
#include "restorer.h"

#include "crtools.h"

struct fmap_fd {
	struct fmap_fd	*next;
	unsigned long	start;
	int		pid;
	int		fd;
};

/*
 * real_pid member formerly served cases when
 * no fork-with-pid functionality were in kernel,
 * so now it is being kept here just in case if
 * we need it again.
 */

struct shmem_info {
	unsigned long	start;
	unsigned long	end;
	unsigned long	shmid;
	int		pid;
	int		real_pid;
};

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
	int		real_pid;
	int		read_fd;
	int		write_fd;
	int		status;
	int		users;
};

struct shmem_id {
	struct shmem_id *next;
	unsigned long	addr;
	unsigned long	end;
	unsigned long	shmid;
};

static struct shmem_id *shmem_ids;

static struct fmap_fd *fmap_fds;

static struct shmem_info *shmems;
static int nr_shmems;

static struct pipe_info *pipes;
static int nr_pipes;

static int restore_task_with_children(int my_pid, char *pstree_path);

static void show_saved_shmems(void)
{
	int i;

	pr_info("\tSaved shmems:\n");

	for (i = 0; i < nr_shmems; i++)
		pr_info("\t\tstart: %016lx shmid: %lx pid: %d\n",
			shmems[i].start,
			shmems[i].shmid,
			shmems[i].pid);
}

static void show_saved_pipes(void)
{
	int i;

	pr_info("\tSaved pipes:\n");
	for (i = 0; i < nr_pipes; i++)
		pr_info("\t\tpipeid %x pid %d users %d status %d\n",
			pipes[i].pipeid, pipes[i].pid,
			pipes[i].users, pipes[i].status);
}

static struct shmem_info *find_shmem(unsigned long addr, unsigned long shmid)
{
	struct shmem_info *si;
	int i;

	for (i = 0; i < nr_shmems; i++) {
		si = shmems + i;
		if (si->start <= addr && si->end >= addr && si->shmid == shmid)
			return si;
	}

	return NULL;
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

static void shmem_update_real_pid(int vpid, int rpid)
{
	int i;

	for (i = 0; i < nr_shmems; i++)
		if (shmems[i].pid == vpid)
			shmems[i].real_pid = rpid;
}

static int shmem_wait_and_open(struct shmem_info *si)
{
	/* FIXME - not good */
	char path[128];
	unsigned long time = 1000;

	sleep(1);

	while (si->real_pid == 0)
		usleep(time);

	sprintf(path, "/proc/%d/map_files/%lx-%lx",
		si->real_pid, si->start, si->end);

	while (1) {
		int ret = open(path, O_RDWR);
		if (ret > 0)
			return ret;

		if (ret < 0 && errno != ENOENT) {
			perror("     Can't stat shmem");
			return -1;
		}

		pr_info("Waiting for [%s] to appear\n", path);
		if (time < 20000000)
			time <<= 1;
		usleep(time);
	}
}

static int collect_shmem(int pid, struct shmem_entry *e)
{
	int i;

	for (i = 0; i < nr_shmems; i++) {
		if (shmems[i].start != e->start ||
		    shmems[i].shmid != e->shmid)
			continue;

		if (shmems[i].end != e->end) {
			pr_err("Bogus shmem\n");
			return 1;
		}

		/*
		 * Only the shared mapping with highest
		 * pid will be created in real, other processes
		 * will wait until the kernel propagate this mapping
		 * into /proc
		 */
		if (shmems[i].pid > pid)
			shmems[i].pid = pid;

		return 0;
	}

	if ((nr_shmems + 1) * sizeof(struct shmem_info) >= 4096) {
		pr_panic("OOM storing shmems\n");
		return 1;
	}

	memset(&shmems[nr_shmems], 0, sizeof(shmems[nr_shmems]));

	shmems[nr_shmems].start		= e->start;
	shmems[nr_shmems].end		= e->end;
	shmems[nr_shmems].shmid		= e->shmid;
	shmems[nr_shmems].pid		= pid;
	shmems[nr_shmems].real_pid	= 0;

	nr_shmems++;

	return 0;
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
		} else if (pipes[i].pid == pid) {
			switch (e->flags) {
			case O_RDONLY:
				pipes[i].status |= PIPE_RDONLY;
				break;
			case O_WRONLY:
				pipes[i].status |= PIPE_WRONLY;
				break;
			}
		}

		pipes[i].users++;

		return 0;
	}

	if ((nr_pipes + 1) * sizeof(struct pipe_info) >= 4096) {
		pr_panic("OOM storing pipes\n");
		return 1;
	}

	memset(&pipes[nr_pipes], 0, sizeof(pipes[nr_pipes]));

	pipes[nr_pipes].pipeid	= e->pipeid;
	pipes[nr_pipes].pid	= pid;
	pipes[nr_pipes].users	= 1;

	switch (e->flags) {
	case O_RDONLY:
		pipes[nr_pipes].status = PIPE_RDONLY;
		break;
	case O_WRONLY:
		pipes[nr_pipes].status = PIPE_WRONLY;
		break;
	default:
		pr_err("%d: Unknown pipe status pipeid %d\n",
		       pid, e->pipeid);
		break;
	}

	nr_pipes++;

	return 0;
}

static int prepare_shmem_pid(int pid)
{
	int sh_fd;
	u32 type = 0;

	sh_fd = open_fmt_ro("shmem-%d.img", pid);
	if (sh_fd < 0) {
		perror("Can't open shmem info");
		return 1;
	}

	read(sh_fd, &type, sizeof(type));
	if (type != SHMEM_MAGIC) {
		perror("Bad shmem magic");
		return 1;
	}

	while (1) {
		struct shmem_entry e;
		int ret;

		ret = read(sh_fd, &e, sizeof(e));
		if (ret == 0)
			break;

		if (ret != sizeof(e)) {
			perror("Can't read shmem entry");
			return 1;
		}

		if (collect_shmem(pid, &e))
			return 1;
	}

	close(sh_fd);
	return 0;
}

static int prepare_pipes_pid(int pid)
{
	int p_fd;
	u32 type = 0;

	p_fd = open_fmt_ro("pipes-%d.img", pid);
	if (p_fd < 0) {
		perror("Can't open pipes image");
		return 1;
	}

	read(p_fd, &type, sizeof(type));
	if (type != PIPES_MAGIC) {
		perror("Bad pipes magin");
		return 1;
	}

	while (1) {
		struct pipe_entry e;
		int ret;

		ret = read(p_fd, &e, sizeof(e));
		if (ret == 0)
			break;
		if (ret != sizeof(e)) {
			pr_perror("Read pipes for %d failed %d of %li read\n",
					pid, ret, sizeof(e));
			return 1;
		}

		if (collect_pipe(pid, &e, p_fd))
			return 1;

		if (e.bytes)
			lseek(p_fd, e.bytes, SEEK_CUR);
	}

	close(p_fd);
	return 0;
}

static int prepare_shared(int ps_fd)
{
	pr_info("Preparing info about shared resources\n");

	nr_shmems = 0;
	shmems = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANON, 0, 0);
	if (shmems == MAP_FAILED) {
		perror("Can't map shmems");
		return 1;
	}

	pipes = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANON, 0, 0);
	if (pipes == MAP_FAILED) {
		perror("Can't map pipes");
		return 1;
	}

	while (1) {
		struct pstree_entry e;
		int ret;

		ret = read(ps_fd, &e, sizeof(e));
		if (ret == 0)
			break;

		if (ret != sizeof(e)) {
			perror("Can't read ps");
			return 1;
		}

		if (prepare_shmem_pid(e.pid))
			return 1;

		if (prepare_pipes_pid(e.pid))
			return 1;

		lseek(ps_fd, e.nr_children * sizeof(u32), SEEK_CUR);
	}

	lseek(ps_fd, sizeof(u32), SEEK_SET);

	show_saved_shmems();
	show_saved_pipes();

	return 0;
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

static int open_fe_fd(struct fdinfo_entry *fe, int fd)
{
	char path[PATH_MAX];
	int tmp;

	if (read(fd, path, fe->len) != fe->len) {
		pr_err("Error reading path");
		return -1;
	}

	path[fe->len] = '\0';

	tmp = open(path, fe->flags);
	if (tmp < 0) {
		pr_perror("Can't open file %s", path);
		return -1;
	}

	lseek(tmp, fe->pos, SEEK_SET);

	return tmp;
}

static int open_fd(int pid, struct fdinfo_entry *fe, int *cfd)
{
	int fd, tmp;

	if (*cfd == (int)fe->addr) {
		tmp = dup(*cfd);
		if (tmp < 0) {
			perror("Can't dup file");
			return 1;
		}

		*cfd = tmp;
	}

	tmp = open_fe_fd(fe, *cfd);
	if (tmp < 0)
		return 1;

	fd = reopen_fd_as((int)fe->addr, tmp);
	if (fd < 0)
		return 1;

	return 0;
}

static int open_fmap(int pid, struct fdinfo_entry *fe, int fd)
{
	int tmp;
	struct fmap_fd *new;

	tmp = open_fe_fd(fe, fd);
	if (tmp < 0)
		return 1;

	pr_info("%d:\t\tWill map %lx to %d\n", pid, (unsigned long)fe->addr, tmp);

	new		= malloc(sizeof(*new));
	new->start	= fe->addr;
	new->fd		= tmp;
	new->next	= fmap_fds;
	new->pid	= pid;

	fmap_fds	= new;

	return 0;
}

static int prepare_fds(int pid)
{
	u32 mag;
	int fdinfo_fd;

	pr_info("%d: Opening files img\n", pid);

	fdinfo_fd = open_fmt_ro("fdinfo-%d.img", pid);
	if (fdinfo_fd < 0) {
		pr_perror("Can't open %d fdinfo", pid);
		return 1;
	}

	read(fdinfo_fd, &mag, 4);
	if (mag != FDINFO_MAGIC) {
		pr_err("Bad %d fdinfo magic number\n", pid);
		return 1;
	}

	while (1) {
		int ret;
		struct fdinfo_entry fe;

		ret = read(fdinfo_fd, &fe, sizeof(fe));
		if (ret == 0) {
			close(fdinfo_fd);
			return 0;
		}

		if (ret < 0) {
			pr_perror("Error reading %d fdinfo\n", pid);
			return 1;
		}

		if (ret != sizeof(fe)) {
			pr_err("Corrupted %d fdinfo\n", pid);
			return 1;
		}

		pr_info("\t%d: Got fd for %lx type %d namelen %d\n", pid,
			(unsigned long)fe.addr, fe.type, fe.len);
		switch (fe.type) {
		case FDINFO_FD:
			if (open_fd(pid, &fe, &fdinfo_fd))
				return 1;
			break;
		case FDINFO_MAP:
			if (open_fmap(pid, &fe, fdinfo_fd))
				return 1;
			break;
		default:
			pr_err("Unknown %d fdinfo file type\n", pid);
			return 1;
		}
	}
}

static unsigned long find_shmem_id(unsigned long addr)
{
	struct shmem_id *si;

	for (si = shmem_ids; si; si = si->next)
		if (si->addr <= addr && si->end >= addr)
			return si->shmid;

	return 0;
}

static void save_shmem_id(struct shmem_entry *e)
{
	struct shmem_id *si;

	si		= malloc(sizeof(*si));
	si->addr	= e->start;
	si->end		= e->end;
	si->shmid	= e->shmid;
	si->next	= shmem_ids;

	shmem_ids	= si;
}

static int prepare_shmem(int pid)
{
	int sh_fd;
	u32 type = 0;

	sh_fd = open_fmt_ro("shmem-%d.img", pid);
	if (sh_fd < 0) {
		perror("Can't open shmem info");
		return 1;
	}

	read(sh_fd, &type, sizeof(type));
	if (type != SHMEM_MAGIC) {
		perror("Bad shmem magic");
		return 1;
	}

	while (1) {
		struct shmem_entry e;
		int ret;

		ret = read(sh_fd, &e, sizeof(e));
		if (ret == 0)
			break;
		if (ret != sizeof(e)) {
			perror("Can't read shmem entry");
			return 1;
		}

		save_shmem_id(&e);
	}

	close(sh_fd);
	return 0;
}

static int try_fixup_file_map(int pid, struct vma_entry *vma_entry, int fd)
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
	return 1;
}

static int try_fixup_shared_map(int pid, struct vma_entry *vi, int fd)
{
	struct shmem_info *si;
	unsigned long shmid;

	shmid = find_shmem_id(vi->start);
	if (!shmid)
		return 0;

	si = find_shmem(vi->start, shmid);
	pr_info("%d: Search for %016lx shmem %p/%d\n", pid, vi->start, si, si ? si->pid : -1);

	if (!si) {
		pr_err("Can't find my shmem %016lx\n", vi->start);
		return 1;
	}

	if (si->pid != pid) {
		int sh_fd;

		sh_fd = shmem_wait_and_open(si);
		pr_info("%d: Fixing %lx vma to %lx/%d shmem -> %d\n",
			pid, vi->start, si->shmid, si->pid, sh_fd);
		if (fd < 0) {
			perror("Can't open shmem");
			return 1;
		}

		lseek(fd, -sizeof(*vi), SEEK_CUR);
		vi->fd = sh_fd;
		if (write(fd, vi, sizeof(*vi)) != sizeof(*vi)) {
			perror("Can't write img");
			return 1;
		}
	}

	return 0;
}

static int fixup_vma_fds(int pid, int fd)
{
	int offset = GET_FILE_OFF_AFTER(struct core_entry);

	lseek(fd, offset, SEEK_SET);

	while (1) {
		struct vma_entry vi;

		if (read(fd, &vi, sizeof(vi)) != sizeof(vi)) {
			perror("Can't read");
			return 1;
		}

		if (vi.start == 0 && vi.end == 0)
			return 0;

		if (!(vi.status & VMA_AREA_REGULAR))
			continue;

		if ((vi.status & VMA_FILE_PRIVATE)	||
		    (vi.status & VMA_FILE_SHARED)	||
		    (vi.status & VMA_ANON_SHARED)) {

			pr_info("%d: Fixing %016lx-%016lx %016lx vma\n",
				pid, vi.start, vi.end, vi.pgoff);
			if (try_fixup_file_map(pid, &vi, fd))
				return 1;

			if (try_fixup_shared_map(pid, &vi, fd))
				return 1;
		}
	}
}

static inline bool should_restore_page(int pid, unsigned long va)
{
	struct shmem_info *si;
	unsigned long shmid;

	/*
	 * If this is not a shmem virtual address
	 * we should restore such page.
	 */
	shmid = find_shmem_id(va);
	if (!shmid)
		return true;

	si = find_shmem(va, shmid);
	return si->pid == pid;
}

static char zpage[PAGE_SIZE];

static int fixup_pages_data(int pid, int fd)
{
	int shfd;
	u32 magic;
	u64 va;

	pr_info("%d: Reading shmem pages img\n", pid);

	shfd = open_fmt_ro("pages-shmem-%d.img", pid);
	if (shfd < 0) {
		pr_perror("Can't open %d shmem image %s", pid);
		return 1;
	}

	read(shfd, &magic, sizeof(magic));
	if (magic != PAGES_MAGIC) {
		pr_err("Bad %d shmem file magic number\n", pid);
		return 1;
	}

	/*
	 * Find out the last page, which must be a zero page.
	 */
	lseek(fd, -sizeof(struct page_entry), SEEK_END);
	read(fd, &va, sizeof(va));
	if (va) {
		pr_panic("Zero-page expected but got %lx\n", (unsigned long)va);
		return 1;
	}

	/*
	 * Since we're to update pages we suppress old zero-page
	 * and will write new one at the end.
	 */
	lseek(fd, -sizeof(struct page_entry), SEEK_END);

	while (1) {
		int ret;

		ret = read(shfd, &va, sizeof(va));
		if (ret == 0)
			break;

		if (ret < 0 || ret != sizeof(va)) {
			pr_perror("Can't read virtual address");
			return 1;
		}

		if (va == 0)
			break;

		if (!should_restore_page(pid, va)) {
			lseek(shfd, PAGE_SIZE, SEEK_CUR);
			continue;
		}

		pr_info("%d: Restoring shared page: %16lx\n",
			pid, va);

		write(fd, &va, sizeof(va));
		sendfile(fd, shfd, NULL, PAGE_SIZE);
	}

	close(shfd);
	va = 0;
	write(fd, &va, sizeof(va));
	write(fd, zpage, sizeof(zpage));

	return 0;
}

static int prepare_image_maps(int fd, int pid)
{
	pr_info("%d: Fixing maps before executing image\n", pid);

	if (fixup_vma_fds(pid, fd))
		return 1;

	if (fixup_pages_data(pid, fd))
		return 1;

	return 0;
}

static int prepare_and_execute_image(int pid)
{
	char path[128], elf_path[128];
	int fd, fd_new;
	struct stat buf;

	fd = open_fmt_ro("core-%d.img", pid);
	if (fd < 0) {
		perror("Can't open exec image");
		return 1;
	}

	if (fstat(fd, &buf)) {
		perror("Can't stat");
		return 1;
	}

	sprintf(path, "core-%d.img.out", pid);
	unlink(path);

	fd_new = open(path, O_RDWR | O_CREAT | O_EXCL, 0700);
	if (fd_new < 0) {
		perror("Can't open new image");
		return 1;
	}

	sprintf(elf_path, "core-%d.elf", pid);
	unlink(elf_path);

	pr_info("%d: Preparing execution image %s (%li bytes)\n", pid, path, buf.st_size);
	if (sendfile(fd_new, fd, NULL, buf.st_size) != buf.st_size) {
		pr_perror("sendfile failed\n");
		return 1;
	}
	close(fd);

	if (fchmod(fd_new, 0700)) {
		perror("Can't prepare exec image");
		return 1;
	}

	if (fstat(fd_new, &buf)) {
		perror("Can't stat");
		return 1;
	}

	pr_info("fd_new: %li bytes\n", buf.st_size);

	if (prepare_image_maps(fd_new, pid))
		return 1;

	sync();

	if (convert_to_elf(elf_path, fd_new))
		return 1;

	sync();
	close(fd_new);

	pr_info("%d/%d EXEC ELF-IMAGE\n", pid, getpid());
	return execl(elf_path, elf_path, NULL);
}

static int create_pipe(int pid, struct pipe_entry *e, struct pipe_info *pi, int pipes_fd)
{
	unsigned long time = 1000;
	int pfd[2], tmp;
	int minusers = 1;

	pr_info("\t%d: Creating pipe %x\n", pid, e->pipeid);

	if (pipe(pfd) < 0) {
		perror("Can't create pipe");
		return 1;
	}

	if (e->bytes) {
		pr_info("\t%d: Splicing data to %d\n", pid, pfd[1]);

		tmp = splice(pipes_fd, NULL, pfd[1], NULL, e->bytes, 0);
		if (tmp != e->bytes) {
			pr_err("Wanted to restore %d bytes, but got %d\n",
			       e->bytes, tmp);
			if (tmp < 0)
				perror("Error splicing data");
			return 1;
		}
	}

	pi->read_fd	= pfd[0];
	pi->write_fd	= pfd[1];
	pi->real_pid	= getpid();

	/*
	 * FIXME: xemul@ reported that this actually
	 * would not work if a task keeps pipe many times
	 * not just two. Need to review and fix propery.
	 */
	if (pipe_is_rw(pi))
		minusers = 2;

	pi->status |= PIPE_CREATED;

	pr_info("\t%d: Done, waiting for others (users %d) on %d pid with r:%d w:%d\n",
		pid, pi->users - minusers, pi->real_pid, pi->read_fd, pi->write_fd);

	while (1) {
		if (pi->users <= minusers) /* only I left here, no need to wait */
			break;

		pr_info("\t%d: Waiting for %x pipe to attach (%d users left)\n",
				pid, e->pipeid, pi->users - minusers);
		if (time < 20000000)
			time <<= 1;
		usleep(time);
	}

	pr_info("\t%d: All is ok - reopening pipe for %d\n", pid, e->fd);
	if (e->flags & O_WRONLY) {
		if (!pipe_is_rw(pi))
			close_safe(&pi->read_fd);
		tmp = reopen_fd_as(e->fd, pi->write_fd);
	} else {
		if (!pipe_is_rw(pi))
			close_safe(&pi->write_fd);
		tmp = reopen_fd_as(e->fd, pi->read_fd);
	}

	if (tmp < 0)
		return 1;

	return 0;
}

static int attach_pipe(int pid, struct pipe_entry *e, struct pipe_info *pi)
{
	char path[128];
	int tmp, fd;

	pr_info("\t%d: Wating for pipe %x to appear\n",
		pid, e->pipeid);

	while (pi->real_pid == 0)
		usleep(1000);

	if (e->flags & O_WRONLY)
		tmp = pi->write_fd;
	else
		tmp = pi->read_fd;

	if (tmp == -1) {
		pr_panic("Attaching closed pipe\n");
		return 1;
	}

	sprintf(path, "/proc/%d/fd/%d", pi->real_pid, tmp);
	pr_info("\t%d: Attaching pipe %s (%d users left)\n",
		pid, path, pi->users - 1);

	fd = open(path, e->flags);
	if (fd < 0) {
		perror("Can't attach pipe");
		return 1;
	}

	pr_info("\t%d: Done, reopening for %d\n", pid, e->fd);
	tmp = reopen_fd_as(e->fd, fd);
	if (tmp < 0)
		return 1;
	pi->users--;

	return 0;

}

static int open_pipe(int pid, struct pipe_entry *e, int *pipes_fd)
{
	struct pipe_info *pi;

	pr_info("\t%d: Opening pipe %x on fd %d\n", pid, e->pipeid, e->fd);
	if (e->fd == *pipes_fd) {
		int tmp;

		tmp = dup(*pipes_fd);
		if (tmp < 0) {
			perror("Can't dup file");
			return 1;
		}

		*pipes_fd = tmp;
	}

	pi = find_pipe(e->pipeid);
	if (!pi) {
		pr_err("BUG: can't find my pipe %x\n", e->pipeid);
		return 1;
	}

	/*
	 * This is somewhat tricky -- in case if a process uses
	 * both pipe ends the pipe should be created but only one
	 * pipe end get connected immediately in create_pipe the
	 * other pipe end should be connected via pipe attaching.
	 */
	if (pi->pid == pid && !(pi->status & PIPE_CREATED))
		return create_pipe(pid, e, pi, *pipes_fd);
	else
		return attach_pipe(pid, e, pi);
}

static int prepare_pipes(int pid)
{
	int pipes_fd;
	u32 type = 0;

	pr_info("%d: Opening pipes\n", pid);

	pipes_fd = open_fmt_ro("pipes-%d.img", pid);
	if (pipes_fd < 0) {
		perror("Can't open pipes img");
		return 1;
	}

	read(pipes_fd, &type, sizeof(type));
	if (type != PIPES_MAGIC) {
		perror("Bad pipes file");
		return 1;
	}

	while (1) {
		struct pipe_entry e;
		int ret;

		ret = read(pipes_fd, &e, sizeof(e));
		if (ret == 0) {
			close(pipes_fd);
			break;
		}

		if (ret != sizeof(e)) {
			perror("Bad pipes entry");
			return 1;
		}

		if (open_pipe(pid, &e, &pipes_fd))
			return 1;
	}

	return 0;
}

static int restore_one_task(int pid)
{
	pr_info("%d: Restoring resources\n", pid);

	if (prepare_pipes(pid))
		return 1;

	if (prepare_fds(pid))
		return 1;

	if (prepare_shmem(pid))
		return 1;

	return prepare_and_execute_image(pid);
}

static int do_child(void *arg)
{
	return restore_task_with_children(getpid(), arg);
}

static inline int fork_with_pid(int pid, char *pstree_path)
{
	int ret = 0;
	void *stack;

	stack = mmap(0, 4 * 4096, PROT_READ | PROT_WRITE,
			MAP_PRIVATE | MAP_ANON | MAP_GROWSDOWN, 0, 0);
	if (stack == MAP_FAILED) {
		pr_perror("mmap failed");
		return -1;
	}

	stack += 4 * 4096;
	ret = clone(do_child, stack, SIGCHLD | CLONE_CHILD_USEPID, pstree_path, NULL, NULL, &pid);
	if (ret < 0)
		pr_perror("clone failed\n");

	return ret;
}

static int restore_task_with_children(int my_pid, char *pstree_path)
{
	int *pids;
	int fd, ret, i;
	struct pstree_entry e;

	pr_info("%d: Starting restore\n", my_pid);

	fd = open(pstree_path, O_RDONLY);
	if (fd < 0) {
		perror("Can't reopen pstree image");
		exit(1);
	}

	lseek(fd, sizeof(u32), SEEK_SET);
	while (1) {
		ret = read(fd, &e, sizeof(e));
		if (ret != sizeof(e)) {
			pr_err("%d: Read returned %d\n", my_pid, ret);
			if (ret < 0)
				perror("Can't read pstree");
			exit(1);
		}

		if (e.pid != my_pid) {
			lseek(fd, e.nr_children * sizeof(u32), SEEK_CUR);
			continue;
		}

		break;
	}

	if (e.nr_children > 0) {
		i = e.nr_children * sizeof(int);
		pids = malloc(i);
		ret = read(fd, pids, i);
		if (ret != i) {
			perror("Can't read children pids");
			exit(1);
		}

		close(fd);

		pr_info("%d: Restoring %d children:\n", my_pid, e.nr_children);
		for (i = 0; i < e.nr_children; i++) {
			pr_info("\tFork %d from %d\n", pids[i], my_pid);
			ret = fork_with_pid(pids[i], pstree_path);
			if (ret < 0)
				exit(1);
		}
	} else
		close(fd);

	shmem_update_real_pid(my_pid, getpid());

	return restore_one_task(my_pid);
}

static int restore_root_task(char *pstree_path, int fd)
{
	struct pstree_entry e;
	int ret;

	ret = read(fd, &e, sizeof(e));
	if (ret != sizeof(e)) {
		perror("Can't read root pstree entry");
		return 1;
	}

	close(fd);

	pr_info("Forking root with %d pid\n", e.pid);
	ret = fork_with_pid(e.pid, pstree_path);
	if (ret < 0)
		return 1;

	wait(NULL);
	return 0;
}

static int restore_all_tasks(pid_t pid)
{
	char path[128];
	int pstree_fd;
	u32 type = 0;

	sprintf(path, "pstree-%d.img", pid);
	pstree_fd = open(path, O_RDONLY);
	if (pstree_fd < 0) {
		perror("Can't open pstree image");
		return 1;
	}

	read(pstree_fd, &type, sizeof(type));
	if (type != PSTREE_MAGIC) {
		perror("Bad pstree magic");
		return 1;
	}

	if (prepare_shared(pstree_fd))
		return 1;

	return restore_root_task(path, pstree_fd);
}

static void restorer_test(pid_t pid)
{
	long code_len, vma_len, args_offset, new_sp;
	void *args_rip, *exec_mem, *exec_start;
	long ret;

	struct restore_core_args *args;
	restorer_fcall_t restorer_fcall;
	char path[64];

	restorer_fcall	= restorer;
	code_len	= restorer_fcall(RESTORER_CMD__GET_SELF_LEN) - (long)restorer;
	args_offset	= restorer_fcall(RESTORER_CMD__GET_ARG_OFFSET) - (long)restorer;
	code_len	= round_up(code_len, 16);
	vma_len		= round_up(code_len + RESTORER_STACK_SIZE, PAGE_SIZE);

	/* VMA we need to run restorer code */
	exec_mem = mmap(0, vma_len,
			PROT_READ | PROT_WRITE | PROT_EXEC,
			MAP_PRIVATE | MAP_ANON, 0, 0);
	if (exec_mem == MAP_FAILED) {
		pr_err("Can't mmap section for restore code\n");
		return;
	}

	/*
	 * Prepare a stack for the restorer. It's a bit
	 * tricky -- since compiler generates function
	 * prologue we need to manually tune up stack
	 * value.
	 */
	exec_start = exec_mem + RESTORER_STACK_SIZE;
	memzero(exec_mem, RESTORER_STACK_SIZE);

	/* Restorer content at the new location */
	memcpy(exec_start, &restorer, code_len);
	restorer_fcall = exec_start;

	/*
	 * Stack pointer in a middle of allocated stack zone.
	 */
	new_sp = (long)exec_mem + RESTORER_STACK_MIDDLE;

	/*
	 * Pass arguments and run a command.
	 */
	snprintf(path, sizeof(path), "core-%d.img", pid);
	args			= (struct restore_core_args *)(exec_start + args_offset);
	args->self_entry	= exec_mem;
	args->self_size		= vma_len;
	strcpy(args->core_path, path);

	/*
	 * An indirect call to restorer, note it never resturns
	 * and restoreing core is extremely destructive.
	 */
	asm volatile(
		"movq %0, %%rbx						\t\n"
		"movq %1, %%rax						\t\n"
		"movl $"__stringify(RESTORER_CMD__RESTORE_CORE)", %%edi	\t\n"
		"movq %%rbx, %%rsp					\t\n"
		"callq *%%rax						\t\n"
		:
		: "g"(new_sp), "g"(exec_start)
		: "rsp", "rdi", "rbx", "rax", "memory");

	/* Just to be sure */
	sys_exit(0);
}

int cr_restore_tasks(pid_t pid, struct cr_options *opts)
{
	restorer_test(pid);

	if (opts->leader_only)
		return restore_one_task(pid);
	return restore_all_tasks(pid);
}
