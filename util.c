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

int reopen_fd_as(int new_fd, int old_fd)
{
	if (old_fd != new_fd) {
		int tmp;
		tmp = fcntl(new_fd, F_GETFD);
		if (tmp != -1 || errno != EBADF) {
			/* Standard descriptors may be reused */
			if (new_fd < 3)
				pr_warning("fd=%d is already used\n", new_fd);
			else {
				pr_perror("fd=%d is already used\n", new_fd);
				return -1;
			}
		}

		tmp = dup2(old_fd, new_fd);
		if (tmp < 0) {
			pr_perror("Dup on %d -> %d failed\n", old_fd, new_fd);
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

int parse_maps(pid_t pid, struct list_head *vma_area_list, bool use_map_files)
{
	struct vma_area *vma_area = NULL;
	u64 start, end, pgoff;
	char big_buffer[1024];
	char path[64];
	unsigned long ino;
	char r,w,x,s;
	int dev_maj, dev_min;
	int ret = -1;

	DIR *map_files_dir = NULL;
	FILE *maps = NULL;

	snprintf(path, sizeof(path), "/proc/%d/maps", pid);
	maps = fopen(path, "r");
	if (!maps) {
		pr_perror("Can't open: %s\n", path);
		goto err;
	}

	if (use_map_files) {
		snprintf(path, sizeof(path), "/proc/%d/map_files", pid);
		map_files_dir = opendir(path);
		if (!map_files_dir) {
			pr_err("Can't open %s, old kernel?\n", path);
			goto err;
		}
	}

	while (fgets(big_buffer, sizeof(big_buffer), maps)) {
		struct stat st_buf;
		int num;

		num = sscanf(big_buffer, "%lx-%lx %c%c%c%c %lx %02x:%02x %lu",
			     &start, &end, &r, &w, &x, &s, &pgoff, &dev_maj,
			     &dev_min, &ino);
		if (num != 10) {
			pr_err("Can't parse: %s", big_buffer);
			goto err;
		}

		vma_area = alloc_vma_area();
		if (!vma_area)
			goto err;

		if (map_files_dir) {
			/* Figure out if it's file mapping */
			snprintf(path, sizeof(path), "%lx-%lx", start, end);

			/*
			 * Note that we "open" it in dumper process space
			 * so later we might refer to it via /proc/self/fd/vm_file_fd
			 * if needed.
			 */
			vma_area->vm_file_fd = openat(dirfd(map_files_dir), path, O_RDONLY);
			if (vma_area->vm_file_fd < 0) {
				if (errno != ENOENT) {
					pr_perror("Failed opening %d's map %Lu\n", pid, start);
					goto err;
				}
			}
		}

		vma_area->vma.start	= start;
		vma_area->vma.end	= end;
		vma_area->vma.pgoff	= pgoff;
		vma_area->vma.prot	= PROT_NONE;

		if (r == 'r')
			vma_area->vma.prot |= PROT_READ;
		if (w == 'w')
			vma_area->vma.prot |= PROT_WRITE;
		if (x == 'x')
			vma_area->vma.prot |= PROT_EXEC;

		if (s == 's')
			vma_area->vma.flags = MAP_SHARED;
		else if (s == 'p')
			vma_area->vma.flags = MAP_PRIVATE;

		if (strstr(big_buffer, "[stack]")) {
			vma_area->vma.status |= VMA_AREA_REGULAR | VMA_AREA_STACK;
			vma_area->vma.flags  |= MAP_GROWSDOWN;
		} else if (strstr(big_buffer, "[vsyscall]")) {
			vma_area->vma.status |= VMA_AREA_VSYSCALL;
		} else if (strstr(big_buffer, "[vdso]")) {
			vma_area->vma.status |= VMA_AREA_REGULAR | VMA_AREA_VDSO;
		} else if (strstr(big_buffer, "[heap]")) {
			vma_area->vma.status |= VMA_AREA_REGULAR | VMA_AREA_HEAP;
		} else {
			vma_area->vma.status = VMA_AREA_REGULAR;
		}

		/*
		 * Some mapping hints for restore, we save this on
		 * disk and restore might need to analyze it.
		 */
		if (vma_area->vm_file_fd >= 0) {

			if (fstat(vma_area->vm_file_fd, &st_buf) < 0) {
				pr_perror("Failed fstat on %d's map %Lu\n", pid, start);
				goto err;
			}
			if (!S_ISREG(st_buf.st_mode)) {
				pr_err("Can't handle non-regular mapping on %d's map %Lu\n", pid, start);
				goto err;
			}

			/*
			 * /dev/zero stands for anon-shared mapping
			 * otherwise it's some file mapping.
			 */
			if (MAJOR(st_buf.st_dev) == 0) {
				if (!(vma_area->vma.flags & MAP_SHARED))
					goto err_bogus_mapping;
				vma_area->vma.flags  |= MAP_ANONYMOUS;
				vma_area->vma.status |= VMA_ANON_SHARED;
				vma_area->shmid = st_buf.st_ino;
			} else {
				if (vma_area->vma.flags & MAP_PRIVATE)
					vma_area->vma.status |= VMA_FILE_PRIVATE;
				else
					vma_area->vma.status |= VMA_FILE_SHARED;
			}
		} else {
			/*
			 * No file but mapping -- anonymous one.
			 */
			if (vma_area->vma.flags & MAP_SHARED) {
				vma_area->vma.status |= VMA_ANON_SHARED;
				vma_area->shmid = ino;
			} else {
				vma_area->vma.status |= VMA_ANON_PRIVATE;
			}
			vma_area->vma.flags  |= MAP_ANONYMOUS;
		}

		list_add_tail(&vma_area->list, vma_area_list);
	}

	vma_area = NULL;
	ret = 0;

err:
	if (maps)
		fclose(maps);

	if (map_files_dir)
		closedir(map_files_dir);

	xfree(vma_area);
	return ret;

err_bogus_mapping:
	pr_err("Bogus mapping %lx-%lx (flags: %x vm_file_fd: %d)\n",
	       vma_area->vma.start, vma_area->vma.end,
	       vma_area->vma.flags, vma_area->vm_file_fd);
	goto err;
}

DIR *opendir_proc(char *fmt, ...)
{
	DIR *dir;
	char path[128];
	va_list args;

	sprintf(path, "/proc/");
	va_start(args, fmt);
	vsnprintf(path + 6, sizeof(path) - 6, fmt, args);
	va_end(args);

	dir = opendir(path);
	if (!dir)
		pr_perror("Can't open %s\n", path);
	return dir;
}

FILE *fopen_proc(char *fmt, char *mode, ...)
{
	FILE *file;
	char fname[128];
	va_list args;

	sprintf(fname, "/proc/");
	va_start(args, mode);
	vsnprintf(fname + 6, sizeof(fname) - 6, fmt, args);
	va_end(args);

	file = fopen(fname, mode);
	if (!file)
		pr_perror("Can't open %s\n", fname);
	return file;
}

FILE *fopen_fmt(char *fmt, char *mode, ...)
{
	FILE *file;
	char fname[128];
	va_list args;

	va_start(args, mode);
	vsnprintf(fname, sizeof(fname), fmt, args);
	va_end(args);

	file = fopen(fname, mode);
	if (!file)
		pr_perror("Can't open %s\n", fname);
	return file;
}

int open_image_ro_nocheck(const char *fmt, int pid)
{
	char path[PATH_MAX];
	int tmp;

	tmp = snprintf(path, sizeof(path), "%s/", image_dir);
	snprintf(path + tmp, sizeof(path) - tmp, fmt, pid);

	tmp = open(path, O_RDONLY);
	if (tmp < 0)
		pr_perror("Can't open image %s for %d\n", fmt, pid);

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
