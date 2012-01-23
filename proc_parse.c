#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <dirent.h>
#include <errno.h>
#include <sys/stat.h>

#include "types.h"
#include "list.h"
#include "util.h"
#include "crtools.h"

#include "proc_parse.h"

int parse_maps(pid_t pid, int pid_dir, struct list_head *vma_area_list, bool use_map_files)
{
	struct vma_area *vma_area = NULL;
	u64 start, end, pgoff;
	char big_buffer[1024];
	unsigned long ino;
	char r,w,x,s;
	int dev_maj, dev_min;
	int ret = -1;

	DIR *map_files_dir = NULL;
	FILE *maps = NULL;

	maps = fopen_proc(pid_dir, "maps");
	if (!maps) {
		pr_perror("Can't open %d's maps\n", pid);
		goto err;
	}

	if (use_map_files) {
		map_files_dir = opendir_proc(pid_dir, "map_files");
		if (!map_files_dir) {
			pr_err("Can't open %d's, old kernel?\n", pid);
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
			char path[32];

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

int parse_pid_stat(pid_t pid, int pid_dir, struct proc_pid_stat *s)
{
	FILE *f;
	char *tok;
	int n;

	f = fopen_proc(pid_dir, "stat");
	if (f == NULL) {
		pr_perror("Can't open %d's stat", pid);
		return -1;
	}

	memset(s, 0, sizeof(*s));
	n = fscanf(f,
	       "%d " PROC_TASK_COMM_LEN_FMT " %c %d %d %d %d %d %u %lu %lu %lu %lu "
	       "%lu %lu %ld %ld %ld %ld %d %d %llu %lu %ld %lu %lu %lu %lu "
	       "%lu %lu %lu %lu %lu %lu %lu %lu %lu %d %d %u %u %llu %lu %ld "
	       "%lu %lu %lu %lu %lu %lu %lu %d",
		&s->pid,
		s->comm,
		&s->state,
		&s->ppid,
		&s->pgid,
		&s->sid,
		&s->tty_nr,
		&s->tty_pgrp,
		&s->flags,
		&s->min_flt,
		&s->cmin_flt,
		&s->maj_flt,
		&s->cmaj_flt,
		&s->utime,
		&s->stime,
		&s->cutime,
		&s->cstime,
		&s->priority,
		&s->nice,
		&s->num_threads,
		&s->zero0,
		&s->start_time,
		&s->vsize,
		&s->mm_rss,
		&s->rsslim,
		&s->start_code,
		&s->end_code,
		&s->start_stack,
		&s->esp,
		&s->eip,
		&s->sig_pending,
		&s->sig_blocked,
		&s->sig_ignored,
		&s->sig_handled,
		&s->wchan,
		&s->zero1,
		&s->zero2,
		&s->exit_signal,
		&s->task_cpu,
		&s->rt_priority,
		&s->policy,
		&s->delayacct_blkio_ticks,
		&s->gtime,
		&s->cgtime,
		&s->start_data,
		&s->end_data,
		&s->start_brk,
		&s->arg_start,
		&s->arg_end,
		&s->env_start,
		&s->env_end,
		&s->exit_code);

	if (n < 52) {
		pr_perror("Parsing %d's stat failed (#fields do not match)", pid);
		return -1;
	}

	s->comm[PROC_TASK_COMM_LEN-1] = '\0';
	tok = strchr(s->comm, ')');
	if (tok)
		*tok = '\0';
	fclose(f);

	return 0;
}
