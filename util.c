#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdbool.h>
#include <limits.h>
#include <signal.h>
#include <limits.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <dirent.h>
#include <sys/sendfile.h>
#include <fcntl.h>

#include <sys/param.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/vfs.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <sys/wait.h>

#include "compiler.h"
#include "types.h"
#include "list.h"
#include "util.h"

#include "crtools.h"

/* /proc/PID/maps can contain not up to date information about stack */
void mark_stack_vma(unsigned long sp, struct list_head *vma_area_list)
{
	struct vma_area *vma_area;
	list_for_each_entry(vma_area, vma_area_list, list) {
		if (in_vma_area(vma_area, sp)) {
			vma_area->vma.status |= VMA_AREA_STACK;
			vma_area->vma.flags  |= MAP_GROWSDOWN;

			/*
			 * The kernel doesn't show stack guard pages on
			 * proc output, so add pages here by hands.
			 */
			vma_area->vma.start -= PAGE_SIZE;
			return;
		}
	}
	BUG();
}

void pr_vma(unsigned int loglevel, const struct vma_area *vma_area)
{
	if (!vma_area)
		return;

	print_on_level(loglevel, "s: 0x%16lx e: 0x%16lx l: %8liK p: 0x%8x f: 0x%8x pg: 0x%8lx "
		       "vf: %s st: %s spc: %-8s shmid: 0x%8lx\n",
		       vma_area->vma.start, vma_area->vma.end,
		       KBYTES(vma_area_len(vma_area)),
		       vma_area->vma.prot,
		       vma_area->vma.flags,
		       vma_area->vma.pgoff,
		       vma_area->vm_file_fd < 0 ? "n" : "y",
		       !vma_area->vma.status ? "--" :
		       ((vma_area->vma.status & VMA_FILE_PRIVATE) ? "FP" :
			((vma_area->vma.status & VMA_FILE_SHARED) ? "FS" :
			 ((vma_area->vma.status & VMA_ANON_SHARED) ? "AS" :
			  ((vma_area->vma.status & VMA_ANON_PRIVATE) ? "AP" : "--")))),
		       !vma_area->vma.status ? "--" :
		       ((vma_area->vma.status & VMA_AREA_STACK) ? "stack" :
			((vma_area->vma.status & VMA_AREA_HEAP) ? "heap" :
			 ((vma_area->vma.status & VMA_AREA_VSYSCALL) ? "vsyscall" :
			  ((vma_area->vma.status & VMA_AREA_VDSO) ? "vdso" : "n")))),
			vma_area->vma.shmid);
}

int close_safe(int *fd)
{
	int ret = 0;
	if (*fd > -1) {
		ret = close(*fd);
		if (!ret)
			*fd = -1;
		else
			pr_perror("Unable to close fd %d", *fd);
	}

	return ret;
}

int reopen_fd_as_safe(char *file, int line, int new_fd, int old_fd, bool allow_reuse_fd)
{
	int tmp;

	if (old_fd != new_fd) {

		if (!allow_reuse_fd) {
			if (fcntl(new_fd, F_GETFD) != -1 || errno != EBADF) {
				if (new_fd < 3) {
					/*
					 * Standard descriptors.
					 */
					pr_warn("fd %d already in use (called at %s:%d)\n",
						new_fd, file, line);
				} else {
					pr_err("fd %d already in use (called at %s:%d)\n",
						new_fd, file, line);
					return -1;
				}
			}
		}

		tmp = dup2(old_fd, new_fd);
		if (tmp < 0) {
			pr_perror("Dup %d -> %d failed (called at %s:%d)",
				  old_fd, new_fd, file, line);
			return tmp;
		}

		/* Just to have error message if failed */
		close_safe(&old_fd);
	}

	return 0;
}

int move_img_fd(int *img_fd, int want_fd)
{
	if (*img_fd == want_fd) {
		int tmp;

		tmp = dup(*img_fd);
		if (tmp < 0) {
			pr_perror("Can't dup file");
			return -1;
		}

		close(*img_fd);

		*img_fd = tmp;
	}

	return 0;
}

static pid_t open_proc_pid = 0;
static int open_proc_fd = -1;
static int proc_dir_fd = -1;

int close_pid_proc(void)
{
	int ret = 0;

	if (open_proc_fd >= 0)
		ret = close(open_proc_fd);

	open_proc_fd = -1;
	open_proc_pid = 0;

	return ret;
}

void close_proc()
{
	close_pid_proc();
	if (proc_dir_fd > 0)
		close(proc_dir_fd);
	proc_dir_fd = -1;
}

int set_proc_fd(int fd)
{
	int sfd = get_service_fd(PROC_FD_OFF);

	sfd = dup2(fd, sfd);
	if (sfd < 0) {
		pr_perror("Can't set proc fd\n");
		return -1;
	}

	proc_dir_fd = sfd;

	return 0;
}

int set_proc_mountpoint(char *path)
{
	int sfd = get_service_fd(PROC_FD_OFF), fd;

	close_proc();

	fd = open(path, O_DIRECTORY | O_RDONLY);
	if (fd == -1) {
		pr_err("Can't open %s\n", path);
		return -1;
	}

	sfd = dup2(fd, sfd);
	close(fd);
	if (sfd < 0) {
		pr_err("Can't set proc fd");
		return -1;
	}

	proc_dir_fd = sfd;

	return 0;
}

inline int open_pid_proc(pid_t pid)
{
	char path[18];
	int fd;

	if (pid == open_proc_pid)
		return open_proc_fd;

	close_pid_proc();

	if (proc_dir_fd == -1) {
		fd = set_proc_mountpoint("/proc");
		if (fd < 0)
			return fd;
	}

	snprintf(path, sizeof(path), "%d", pid);
	fd = openat(proc_dir_fd, path, O_RDONLY);
	if (fd < 0)
		pr_perror("Can't open %s", path);
	else {
		open_proc_fd = fd;
		open_proc_pid = pid;
	}

	return fd;
}

int do_open_proc(pid_t pid, int flags, const char *fmt, ...)
{
	char path[128];
	va_list args;
	int dirfd = open_pid_proc(pid);

	if (dirfd < 0)
		return -1;

	va_start(args, fmt);
	vsnprintf(path, sizeof(path), fmt, args);
	va_end(args);

	return openat(dirfd, path, flags);
}

static int service_fd_rlim_cur;

int init_service_fd(void)
{
	struct rlimit rlimit;

	/*
	 * Service FDs are thouse that most likely won't
	 * conflict with any 'real-life' ones
	 */

	if (getrlimit(RLIMIT_NOFILE, &rlimit)) {
		pr_perror("Can't get rlimit");
		return -1;
	}

	service_fd_rlim_cur = (int)rlimit.rlim_cur;
	BUG_ON(service_fd_rlim_cur < SERVICE_FD_MAX);

	return 0;
}

int get_service_fd(enum sfd_type type)
{
	BUG_ON((int)type <= SERVICE_FD_MIN || (int)type >= SERVICE_FD_MAX);
	return service_fd_rlim_cur - type;
}

bool is_service_fd(int fd, enum sfd_type type)
{
	return fd == get_service_fd(type);
}

int copy_file(int fd_in, int fd_out, size_t bytes)
{
	ssize_t written = 0;
	size_t chunk = bytes ? bytes : 4096;

	while (1) {
		ssize_t ret;

		ret = sendfile(fd_out, fd_in, NULL, chunk);
		if (ret < 0) {
			pr_perror("Can't send data to ghost file");
			return -1;
		}

		if (ret == 0) {
			if (bytes && (written != bytes)) {
				pr_err("Ghost file size mismatch %lu/%lu\n",
						written, bytes);
				return -1;
			}
			break;
		}

		written += ret;
	}

	return 0;
}

#ifndef ANON_INODE_FS_MAGIC
# define ANON_INODE_FS_MAGIC 0x09041934
#endif

bool is_anon_inode(struct statfs *statfs)
{
	return statfs->f_type == ANON_INODE_FS_MAGIC;
}

int is_anon_link_type(int lfd, char *type)
{
	char link[32], aux[32];
	ssize_t ret;

	snprintf(aux, sizeof(aux), "/proc/self/fd/%d", lfd);
	ret = readlink(aux, link, sizeof(link));
	if (ret < 0) {
		pr_perror("Can't read link of fd %d\n", lfd);
		return 0;
	}
	link[ret] = 0;
	snprintf(aux, sizeof(aux), "anon_inode:%s", type);
	return !strcmp(link, aux);
}

static void *sh_buf;
static unsigned int sh_bytes_left;
static size_t sh_last_size;
#define SH_BUF_CHUNK	4096

void *shmalloc(size_t bytes)
{
	void *ret;

	if (bytes > SH_BUF_CHUNK) {
		pr_err("Too big shared buffer requested %lu\n", bytes);
		return NULL;
	}

	if (sh_bytes_left < bytes) {
		sh_buf = mmap(NULL, SH_BUF_CHUNK, PROT_READ | PROT_WRITE,
				MAP_SHARED | MAP_ANON, 0, 0);
		if (sh_buf == MAP_FAILED) {
			pr_perror("Can't alloc shared buffer");
			return NULL;
		}

		sh_bytes_left = SH_BUF_CHUNK;
	}

	ret = sh_buf;
	sh_buf += bytes;
	sh_bytes_left -= bytes;
	sh_last_size = bytes;

	return ret;
}

/* Only last chunk can be released */
void shfree_last(void *ptr)
{
	BUG_ON(sh_buf - sh_last_size != ptr);
	sh_buf -= sh_last_size;
	sh_bytes_left += sh_last_size;
	sh_last_size = 0;
}

int run_scripts(char *action)
{
	struct script *script;
	int ret = 0;

	if (setenv("CRTOOLS_SCRIPT_ACTION", action, 1)) {
		pr_perror("Can't set CRTOOL_SCRIPT_ACTION=%s\n", action);
		return -1;
	}

	list_for_each_entry(script, &opts.scripts, node)
		ret |= system(script->path);

	unsetenv("CRTOOLS_SCRIPT_ACTION");
	return ret;
}
