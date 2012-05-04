#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <dirent.h>
#include <errno.h>
#include <sys/stat.h>
#include <string.h>

#include "types.h"
#include "list.h"
#include "util.h"
#include "crtools.h"

#include "proc_parse.h"

struct buffer {
	char buf[PAGE_SIZE];
	char end; /* '\0' */
};

static struct buffer __buf;
static char *buf = __buf.buf;

#define BUF_SIZE sizeof(__buf.buf)

int parse_maps(pid_t pid, struct list_head *vma_area_list, bool use_map_files)
{
	struct vma_area *vma_area = NULL;
	u64 start, end, pgoff;
	unsigned long ino;
	char r,w,x,s;
	int dev_maj, dev_min;
	int ret = -1, nr = 0;

	DIR *map_files_dir = NULL;
	FILE *maps = NULL;

	maps = fopen_proc(pid, "maps");
	if (!maps)
		goto err;

	if (use_map_files) {
		map_files_dir = opendir_proc(pid, "map_files");
		if (!map_files_dir) /* old kernel? */
			goto err;
	}

	while (fgets(buf, BUF_SIZE, maps)) {
		int num;
		char file_path[6];


		memset(file_path, 0, 6);
		num = sscanf(buf, "%lx-%lx %c%c%c%c %lx %02x:%02x %lu %5s",
			     &start, &end, &r, &w, &x, &s, &pgoff, &dev_maj,
			     &dev_min, &ino, file_path);
		if (num < 10) {
			pr_err("Can't parse: %s", buf);
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
					pr_perror("Can't open %d's map %lu", pid, start);
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
		else {
			pr_err("Unexpected VMA met (%c)\n", s);
			goto err;
		}

		if (strstr(buf, "[stack")) {
			vma_area->vma.status |= VMA_AREA_REGULAR | VMA_AREA_STACK;
			vma_area->vma.flags  |= MAP_GROWSDOWN;
		} else if (strstr(buf, "[vsyscall]")) {
			vma_area->vma.status |= VMA_AREA_VSYSCALL;
		} else if (strstr(buf, "[vdso]")) {
			vma_area->vma.status |= VMA_AREA_REGULAR | VMA_AREA_VDSO;
		} else if (strstr(buf, "[heap]")) {
			vma_area->vma.status |= VMA_AREA_REGULAR | VMA_AREA_HEAP;
		} else {
			vma_area->vma.status = VMA_AREA_REGULAR;
		}

		/*
		 * Some mapping hints for restore, we save this on
		 * disk and restore might need to analyze it.
		 */
		if (vma_area->vm_file_fd >= 0) {
			struct stat st_buf;

			if (fstat(vma_area->vm_file_fd, &st_buf) < 0) {
				pr_perror("Failed fstat on %d's map %lu", pid, start);
				goto err;
			}
			if (!S_ISREG(st_buf.st_mode)) {
				pr_err("Can't handle non-regular mapping on %d's map %lu\n", pid, start);
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
				vma_area->vma.shmid = st_buf.st_ino;

				if (!strcmp(file_path, "/SYSV")) {
					pr_info("path: %s\n", file_path);
					vma_area->vma.status |= VMA_AREA_SYSVIPC;
				}
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
				vma_area->vma.shmid = ino;
			} else {
				vma_area->vma.status |= VMA_ANON_PRIVATE;
			}
			vma_area->vma.flags  |= MAP_ANONYMOUS;
		}

		list_add_tail(&vma_area->list, vma_area_list);
		nr++;
	}

	vma_area = NULL;
	ret = nr;

err:
	if (maps)
		fclose(maps);

	if (map_files_dir)
		closedir(map_files_dir);

	xfree(vma_area);
	return ret;

err_bogus_mapping:
	pr_err("Bogus mapping 0x%lx-0x%lx (flags: %#x vm_file_fd: %d)\n",
	       vma_area->vma.start, vma_area->vma.end,
	       vma_area->vma.flags, vma_area->vm_file_fd);
	goto err;
}

int parse_pid_stat_small(pid_t pid, struct proc_pid_stat_small *s)
{
	char *tok, *p;
	int fd;
	int n;

	fd = open_proc(pid, "stat");
	if (fd < 0)
		return -1;

	n = read(fd, buf, BUF_SIZE);
	if (n < 1) {
		pr_err("stat for %d is corrupted\n", pid);
		close(fd);
		return -1;
	}
	close(fd);

	memset(s, 0, sizeof(*s));

	tok = strchr(buf, ' ');
	if (!tok)
		goto err;
	*tok++ = '\0';
	if (*tok != '(')
		goto err;

	s->pid = atoi(buf);

	p = strrchr(tok + 1, ')');
	if (!p)
		goto err;
	*tok = '\0';
	*p = '\0';

	strncpy(s->comm, tok + 1, sizeof(s->comm));

	n = sscanf(p + 1, " %c %d %d %d", &s->state, &s->ppid, &s->pgid, &s->sid);
	if (n < 4)
		goto err;

	return 0;

err:
	pr_err("Parsing %d's stat failed (#fields do not match)\n", pid);
	return -1;
}

int parse_pid_stat(pid_t pid, struct proc_pid_stat *s)
{
	char *tok, *p;
	int fd;
	int n;

	fd = open_proc(pid, "stat");
	if (fd < 0)
		return -1;

	n = read(fd, buf, BUF_SIZE);
	if (n < 1) {
		pr_err("stat for %d is corrupted\n", pid);
		close(fd);
		return -1;
	}
	close(fd);

	memset(s, 0, sizeof(*s));

	tok = strchr(buf, ' ');
	if (!tok)
		goto err;
	*tok++ = '\0';
	if (*tok != '(')
		goto err;

	s->pid = atoi(buf);

	p = strrchr(tok + 1, ')');
	if (!p)
		goto err;
	*tok = '\0';
	*p = '\0';

	strncpy(s->comm, tok + 1, sizeof(s->comm));

	n = sscanf(p + 1,
	       " %c %d %d %d %d %d %u %lu %lu %lu %lu "
	       "%lu %lu %ld %ld %ld %ld %d %d %llu %lu %ld %lu %lu %lu %lu "
	       "%lu %lu %lu %lu %lu %lu %lu %lu %lu %d %d %u %u %llu %lu %ld "
	       "%lu %lu %lu %lu %lu %lu %lu %d",
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
	if (n < 50)
		goto err;

	return 0;

err:
	pr_err("Parsing %d's stat failed (#fields do not match)\n", pid);
	return -1;
}

static int ids_parse(char *str, unsigned int *arr)
{
	char *end;

	arr[0] = strtol(str, &end, 10);
	arr[1] = strtol(end + 1, &end, 10);
	arr[2] = strtol(end + 1, &end, 10);
	arr[3] = strtol(end + 1, &end, 10);
	if (*end != '\n')
		return -1;
	else
		return 0;
}

static int cap_parse(char *str, unsigned int *res)
{
	int i, ret;

	for (i = 0; i < PROC_CAP_SIZE; i++) {
		ret = sscanf(str, "%08x", &res[PROC_CAP_SIZE - 1 - i]);
		if (ret != 1)
			return -1;
		str += 8;
	}

	return 0;
}

int parse_pid_status(pid_t pid, struct proc_status_creds *cr)
{
	int done = 0;
	FILE *f;
	char str[64];

	f = fopen_proc(pid, "status");
	if (f == NULL) {
		pr_perror("Can't open proc status");
		return -1;
	}

	while (done < 6 && fgets(str, sizeof(str), f)) {
		if (!strncmp(str, "Uid:", 4)) {
			if (ids_parse(str + 5, cr->uids))
				goto err_parse;

			done++;
		}

		if (!strncmp(str, "Gid:", 4)) {
			if (ids_parse(str + 5, cr->gids))
				goto err_parse;

			done++;
		}

		if (!strncmp(str, "CapInh:", 7)) {
			if (cap_parse(str + 8, cr->cap_inh))
				goto err_parse;

			done++;
		}

		if (!strncmp(str, "CapEff:", 7)) {
			if (cap_parse(str + 8, cr->cap_eff))
				goto err_parse;

			done++;
		}

		if (!strncmp(str, "CapPrm:", 7)) {
			if (cap_parse(str + 8, cr->cap_prm))
				goto err_parse;

			done++;
		}

		if (!strncmp(str, "CapBnd:", 7)) {
			if (cap_parse(str + 8, cr->cap_bnd))
				goto err_parse;

			done++;
		}
	}

	if (done != 6) {
err_parse:
		pr_err("Error parsing proc status file\n");
		fclose(f);
		return -1;
	}

	fclose(f);
	return 0;
}

int parse_mountinfo(pid_t pid, struct proc_mountinfo *mi, int nr_elems)
{
	FILE *f = NULL;
	char str[256];
	int i = 0;

	snprintf(str, sizeof(str), "/proc/%d/mountinfo", pid);
	f = fopen(str, "r");
	if (!f) {
		pr_perror("Can't open %d mountinfo", pid);
		return -1;
	}

	while (fgets(str, sizeof(str), f)) {
		unsigned int kmaj, kmin, parent_mnt_id;
		char parent_mnt_root[63];
		int ret;

		if ((i + 1) >= nr_elems) {
			i = -ENOMEM;
			goto out_close;
		}

		ret = sscanf(str, "%i %i %u:%u %63s %63s",
			     &mi[i].mnt_id, &parent_mnt_id,
			     &kmaj, &kmin, parent_mnt_root,
			     mi[i].mnt_root);
		if (ret != 6) {
			pr_err("Bad format in %d mountinfo\n", pid);
			i = -1;
			goto out_close;
		}

		mi[i].s_dev = MKKDEV(kmaj, kmin);
		i++;
	}

out_close:
	fclose(f);
out:
	return i;
}
