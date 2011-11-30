#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdbool.h>
#include <limits.h>

#include <sys/param.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <limits.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <dirent.h>

#include <fcntl.h>

#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/vfs.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>

#include "compiler.h"
#include "types.h"
#include "list.h"
#include "util.h"

#include "crtools.h"

void printk(const char *format, ...)
{
	va_list params;

	va_start(params, format);
	vfprintf(stdout, format, params);
	va_end(params);
}

int ptrace_show_area_r(pid_t pid, void *addr, long bytes)
{
	unsigned long w, i;
	if (bytes & (sizeof(long) - 1))
		return -1;
	for (w = 0; w < bytes / sizeof(long); w++) {
		unsigned long *a = addr;
		unsigned long v;
		v = ptrace(PTRACE_PEEKDATA, pid, a + w, NULL);
		if (v == -1U && errno)
			goto err;
		else {
			unsigned char *c = (unsigned char *)&v;
			for (i = sizeof(v)/sizeof(*c); i > 0; i--)
				printk("%02x ", c[i - 1]);
			printk("  ");
		}
	}
	printk("\n");
	return 0;
err:
	return -2;
}

int ptrace_show_area(pid_t pid, void *addr, long bytes)
{
	unsigned long w, i;
	if (bytes & (sizeof(long) - 1))
		return -1;
	printk("%016lx: ", (unsigned long)addr);
	for (w = 0; w < bytes / sizeof(long); w++) {
		unsigned long *a = addr;
		unsigned long v;
		v = ptrace(PTRACE_PEEKDATA, pid, a + w, NULL);
		if (v == -1U && errno)
			goto err;
		else {
			unsigned char *c = (unsigned char *)&v;
			for (i = 0; i < sizeof(v)/sizeof(*c); i++)
				printk("%02x ", c[i]);
			printk("  ");
		}
	}
	printk("\n");
	return 0;
err:
	return -2;
}

int ptrace_peek_area(pid_t pid, void *dst, void *addr, long bytes)
{
	unsigned long w;
	if (bytes & (sizeof(long) - 1))
		return -1;
	for (w = 0; w < bytes / sizeof(long); w++) {
		unsigned long *d = dst, *a = addr;
		d[w] = ptrace(PTRACE_PEEKDATA, pid, a + w, NULL);
		if (d[w] == -1U && errno)
			goto err;
	}
	return 0;
err:
	return -2;
}

int ptrace_poke_area(pid_t pid, void *src, void *addr, long bytes)
{
	unsigned long w;
	if (bytes & (sizeof(long) - 1))
		return -1;
	for (w = 0; w < bytes / sizeof(long); w++) {
		unsigned long *s = src, *a = addr;
		if (ptrace(PTRACE_POKEDATA, pid, a + w, s[w]))
			goto err;
	}
	return 0;
err:
	return -2;
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

void printk_registers(user_regs_struct_t *regs)
{
	printk("ip     : %16lx cs     : %16lx ds     : %16lx\n"
	       "es     : %16lx fs     : %16lx gs     : %16lx\n"
	       "sp     : %16lx ss     : %16lx flags  : %16lx\n"
	       "ax     : %16lx cx     : %16lx dx     : %16lx\n"
	       "si     : %16lx di     : %16lx bp     : %16lx\n"
	       "bx     : %16lx r8     : %16lx r9     : %16lx\n"
	       "r10    : %16lx r11    : %16lx r12    : %16lx\n"
	       "r13    : %16lx r14    : %16lx r15    : %16lx\n"
	       "orig_ax: %16lx fs_base: %16lx gs_base: %16lx\n\n",
	       regs->ip, regs->cs, regs->ds,
	       regs->es, regs->fs, regs->gs,
	       regs->sp, regs->ss, regs->flags,
	       regs->ax, regs->cx, regs->dx,
	       regs->si, regs->di, regs->bp,
	       regs->bx, regs->r8, regs->r9,
	       regs->r10, regs->r11, regs->r12,
	       regs->r13, regs->r14, regs->r15,
	       regs->orig_ax, regs->fs_base, regs->gs_base);
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
		int tmp = dup2(old_fd, new_fd);
		if (tmp < 0) {
			pr_perror("Dup on %d -> %d failed\n", old_fd, new_fd);
			return tmp;
		}

		/* Just to have error message if failed */
		close_safe(&old_fd);
	}

	return new_fd;
}

int parse_maps(pid_t pid, struct list_head *vma_area_list, bool use_map_files)
{
	struct vma_area *vma_area = NULL;
	u64 start, end, pgoff;
	char map_files_path[64];
	char big_buffer[1024];
	char maps_path[64];
	unsigned long ino;
	char r,w,x,s;
	int dev_maj, dev_min;
	int ret = -1;

	DIR *map_files_dir = NULL;
	FILE *maps = NULL;

	snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
	maps = fopen(maps_path, "r");
	if (!maps) {
		pr_perror("Can't open: %s\n", maps_path);
		goto err;
	}

	snprintf(map_files_path, sizeof(map_files_path),
		 "/proc/%d/map_files", pid);

	/*
	 * It might be a problem in kernel, either
	 * I'm debugging it on old kernel ;)
	 */
	map_files_dir = opendir(map_files_path);
	if (use_map_files && !map_files_dir) {
		pr_err("Can't open %s, old kernel?\n",
		       map_files_path);
		goto err;
	}

	while (fgets(big_buffer, sizeof(big_buffer), maps)) {
		char vma_file_path[16+16+2];
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

		/* Figure out if it's file mapping */
		snprintf(vma_file_path, sizeof(vma_file_path), "%lx-%lx", start, end);

		if (map_files_dir) {
			/*
			 * Note that we "open" it in dumper process space
			 * so later we might refer to it via /proc/self/fd/vm_file_fd
			 * if needed.
			 */
			vma_area->vm_file_fd = openat(dirfd(map_files_dir),
						      vma_file_path, O_RDONLY);
			if (vma_area->vm_file_fd < 0) {
				if (errno != ENOENT) {
					pr_perror("Failed opening %s/%s\n",
						  map_files_path,
						  vma_file_path);
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
				pr_perror("Failed fstat on %s%s\n",
					  map_files_path,
					  vma_file_path);
				goto err;
			}
			if (!S_ISREG(st_buf.st_mode)) {
				pr_err("Can't handle non-regular "
				       "mapping on %s%s\n",
				       map_files_path,
				       vma_file_path);
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
			if (vma_area->vma.flags & MAP_SHARED)
				goto err_bogus_mapping;

			vma_area->vma.flags  |= MAP_ANONYMOUS;
			vma_area->vma.status |= VMA_ANON_PRIVATE;
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
	pr_err("Bogus mapping %lx-%lx\n",
	       vma_area->vma.start,
	       vma_area->vma.end);
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

int open_fmt(char *fmt, int mode, ...)
{
	int fd;
	char fname[128];
	va_list args;

	va_start(args, mode);
	vsnprintf(fname, sizeof(fname), fmt, args);
	va_end(args);

	fd = open(fname, mode);
	if (fd < 0)
		pr_perror("Can't open %s\n", fname);
	return fd;
}
