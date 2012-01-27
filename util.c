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
#include <sys/user.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <sys/wait.h>

#include "compiler.h"
#include "types.h"
#include "list.h"
#include "util.h"
#include "log.h"

#include "crtools.h"

void printk(const char *format, ...)
{
	va_list params;

	va_start(params, format);
	vdprintf(get_logfd(), format, params);
	va_end(params);
}

void hex_dump(void *addr, unsigned long len)
{
	unsigned char *p = addr;
	unsigned long i;

	len = (len + 8) & ~7;

	for (i = 0; i < len; i += 8) {
		printk("%08lx: %02x %02x %02x %02x %02x %02x %02x %02x\n",
		       p, p[i+0], p[i+1], p[i+2], p[i+3],
		       p[i+4], p[i+5], p[i+6], p[i+7]);
	}
}

void printk_siginfo(siginfo_t *siginfo)
{
	printk("si_signo %d si_errno %d si_code %d\n",
	       siginfo->si_signo, siginfo->si_errno, siginfo->si_code);
}

void printk_vma(struct vma_area *vma_area)
{
	if (!vma_area)
		return;

	printk("s: %16lx e: %16lx l: %4liK p: %8x f: %8x pg: %8lx "
	       "vf: %s st: %s spc: %s\n",
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
		  ((vma_area->vma.status & VMA_AREA_VDSO) ? "vdso" : "n")))));
}

int close_safe(int *fd)
{
	int ret = 0;
	if (*fd > -1) {
		ret = close(*fd);
		if (!ret)
			*fd = -1;
		else
			pr_perror("Unable to close fd: %d\n", *fd);
	}

	return ret;
}

int reopen_fd_as_safe(int new_fd, int old_fd, bool allow_reuse_fd)
{
	int tmp;

	if (old_fd != new_fd) {

		if (!allow_reuse_fd) {
			if (fcntl(new_fd, F_GETFD) != -1 || errno != EBADF) {
				if (new_fd < 3) {
					/*
					 * Standart descriptors.
					 */
					pr_warning("fd = %d is already used\n", new_fd);
				} else {
					pr_err("fd = %d is already used\n", new_fd);
					return -1;
				}
			}
		}

		tmp = dup2(old_fd, new_fd);
		if (tmp < 0) {
			pr_perror("Dup %d -> %d failed\n", old_fd, new_fd);
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
			pr_perror("Can't dup file\n");
			return -1;
		}

		close(*img_fd);

		*img_fd = tmp;
	}

	return 0;
}

int get_image_path(char *path, int size, const char *fmt, int pid)
{
	int len;

	len = snprintf(path, size, "%s/", image_dir);
	len += snprintf(path + len, size - len, fmt, pid);
	if (len > size) {
		pr_err("Image path buffer overflow %d/%d\n", size, len);
		return -1;
	}

	return 0;
}

int open_image_ro_nocheck(const char *fmt, int pid)
{
	char path[PATH_MAX];
	int tmp;

	tmp = get_image_path(path, sizeof(path), fmt, pid);
	if (tmp == 0)
		tmp = open(path, O_RDONLY);
	if (tmp < 0)
		pr_warning("Can't open image %s for %d: %m\n", fmt, pid);

	return tmp;
}

int open_image_ro(int type, int pid)
{
	int fd;
	u32 magic = 0;

	fd = open_image_ro_nocheck(fdset_template[type].fmt, pid);
	if (fd < 0)
		return fd;

	read(fd, &magic, sizeof(magic));
	if (magic != fdset_template[type].magic) {
		pr_err("Magic mismatch for %d of %d\n", type, pid);
		close(fd);
		return -1;
	}

	return fd;
}

int open_pid_proc(pid_t pid)
{
	char path[18];
	int fd;

	sprintf(path, "/proc/%d", pid);
	fd = open(path, O_RDONLY);
	if (fd < 0)
		pr_perror("Can't open %s\n", path);
	return fd;
}

#define do_open_proc(pid_dir_fd, fmt)				\
	({							\
		char fname[64];					\
		va_list args;					\
								\
		va_start(args, fmt);				\
		vsnprintf(fname, sizeof(fname), fmt, args);	\
		va_end(args);					\
								\
		openat(pid_dir_fd, fname, O_RDONLY);		\
	})

int open_proc(int pid_dir_fd, char *fmt, ...)
{
	return do_open_proc(pid_dir_fd, fmt);
}

DIR *opendir_proc(int pid_dir_fd, char *fmt, ...)
{
	int dirfd;

	dirfd = do_open_proc(pid_dir_fd, fmt);
	if (dirfd >= 0)
		return fdopendir(dirfd);

	return NULL;
}

FILE *fopen_proc(int pid_dir_fd, char *fmt, ...)
{
	int fd;

	fd = do_open_proc(pid_dir_fd, fmt);
	if (fd >= 0)
		return fdopen(fd, "r");

	return NULL;
}
