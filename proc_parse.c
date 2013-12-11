#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <dirent.h>
#include <errno.h>
#include <sys/stat.h>
#include <string.h>
#include <linux/fs.h>

#include "asm/types.h"
#include "list.h"
#include "util.h"
#include "mount.h"
#include "mman.h"
#include "cpu.h"
#include "file-lock.h"
#include "pstree.h"
#include "fsnotify.h"
#include "posix-timer.h"
#include "kerndat.h"
#include "vdso.h"
#include "vma.h"

#include "proc_parse.h"
#include "protobuf.h"
#include "protobuf/fdinfo.pb-c.h"

#include <stdlib.h>

struct buffer {
	char buf[PAGE_SIZE];
	char end; /* '\0' */
};

static struct buffer __buf;
static char *buf = __buf.buf;

#define BUF_SIZE sizeof(__buf.buf)

int parse_cpuinfo_features(int (*handler)(char *tok))
{
	FILE *cpuinfo;

	cpuinfo = fopen("/proc/cpuinfo", "r");
	if (!cpuinfo) {
		pr_perror("Can't open cpuinfo file");
		return -1;
	}

	while (fgets(buf, BUF_SIZE, cpuinfo)) {
		char *tok;

		if (strncmp(buf, "flags\t\t:", 8))
			continue;

		for (tok = strtok(buf, " \t\n"); tok;
		     tok = strtok(NULL, " \t\n")) {
			if (handler(tok) < 0)
				break;
		}
	}

	fclose(cpuinfo);
	return 0;
}

/* check the @line starts with "%lx-%lx" format */
static bool is_vma_range_fmt(char *line)
{
	while (*line && is_hex_digit(*line))
		line++;

	if (*line++ != '-')
		return false;

	while (*line && is_hex_digit(*line))
		line++;

	if (*line++ != ' ')
		return false;

	return true;
}

static int parse_vmflags(char *buf, struct vma_area *vma_area)
{
	char *tok;

	if (!buf[0])
		return 0;

	tok = strtok(buf, " \n");
	if (!tok)
		return 0;

#define _vmflag_match(_t, _s) (_t[0] == _s[0] && _t[1] == _s[1])

	do {
		/* mmap() block */
		if (_vmflag_match(tok, "gd"))
			vma_area->vma.flags |= MAP_GROWSDOWN;
		else if (_vmflag_match(tok, "lo"))
			vma_area->vma.flags |= MAP_LOCKED;
		else if (_vmflag_match(tok, "nr"))
			vma_area->vma.flags |= MAP_NORESERVE;
		else if (_vmflag_match(tok, "ht"))
			vma_area->vma.flags |= MAP_HUGETLB;

		/* madvise() block */
		if (_vmflag_match(tok, "sr"))
			vma_area->vma.madv |= (1ul << MADV_SEQUENTIAL);
		else if (_vmflag_match(tok, "rr"))
			vma_area->vma.madv |= (1ul << MADV_RANDOM);
		else if (_vmflag_match(tok, "dc"))
			vma_area->vma.madv |= (1ul << MADV_DONTFORK);
		else if (_vmflag_match(tok, "dd"))
			vma_area->vma.madv |= (1ul << MADV_DONTDUMP);
		else if (_vmflag_match(tok, "mg"))
			vma_area->vma.madv |= (1ul << MADV_MERGEABLE);
		else if (_vmflag_match(tok, "hg"))
			vma_area->vma.madv |= (1ul << MADV_HUGEPAGE);
		else if (_vmflag_match(tok, "nh"))
			vma_area->vma.madv |= (1ul << MADV_NOHUGEPAGE);

		/*
		 * Anything else is just ignored.
		 */
	} while ((tok = strtok(NULL, " \n")));

#undef _vmflag_match

	if (vma_area->vma.madv)
		vma_area->vma.has_madv = true;

	return 0;
}

static inline int is_anon_shmem_map(dev_t dev)
{
	return kerndat_shmem_dev == dev;
}

int parse_smaps(pid_t pid, struct vm_area_list *vma_area_list, bool use_map_files)
{
	struct vma_area *vma_area = NULL;
	unsigned long start, end, pgoff;
	bool prev_growsdown = false;
	unsigned long ino;
	char r, w, x, s;
	int dev_maj, dev_min;
	int ret = -1;

	DIR *map_files_dir = NULL;
	FILE *smaps = NULL;

	vma_area_list->nr = 0;
	vma_area_list->longest = 0;
	vma_area_list->priv_size = 0;
	INIT_LIST_HEAD(&vma_area_list->h);

	smaps = fopen_proc(pid, "smaps");
	if (!smaps)
		goto err;

	if (use_map_files) {
		map_files_dir = opendir_proc(pid, "map_files");
		if (!map_files_dir) /* old kernel? */
			goto err;
	}

	while (1) {
		int num;
		char file_path[6];
		bool eof;

		eof = (fgets(buf, BUF_SIZE, smaps) == NULL);

		if (!eof && !is_vma_range_fmt(buf)) {
			if (!strncmp(buf, "Nonlinear", 9)) {
				BUG_ON(!vma_area);
				pr_err("Nonlinear mapping found %016"PRIx64"-%016"PRIx64"\n",
				       vma_area->vma.start, vma_area->vma.end);
				/*
				 * VMA is already on list and will be
				 * freed later as list get destroyed.
				 */
				vma_area = NULL;
				goto err;
			} else if (!strncmp(buf, "VmFlags: ", 9)) {
				BUG_ON(!vma_area);
				if (parse_vmflags(&buf[9], vma_area))
					goto err;
				continue;
			} else
				continue;
		}

		if (vma_area) {
			/* If we've split the stack vma, only the lowest one has the guard page. */
			if ((vma_area->vma.flags & MAP_GROWSDOWN) && !prev_growsdown)
				vma_area->vma.start -= PAGE_SIZE; /* Guard page */
			prev_growsdown = (bool)(vma_area->vma.flags & MAP_GROWSDOWN);

			list_add_tail(&vma_area->list, &vma_area_list->h);
			vma_area_list->nr++;
			if (privately_dump_vma(vma_area)) {
				unsigned long pages;

				pages = vma_area_len(vma_area) / PAGE_SIZE;
				vma_area_list->priv_size += pages;
				vma_area_list->longest = max(vma_area_list->longest, pages);
			}
		}

		if (eof)
			break;

		vma_area = alloc_vma_area();
		if (!vma_area)
			goto err;

		memset(file_path, 0, 6);
		num = sscanf(buf, "%lx-%lx %c%c%c%c %lx %x:%x %lu %5s",
			     &start, &end, &r, &w, &x, &s, &pgoff, &dev_maj,
			     &dev_min, &ino, file_path);
		if (num < 10) {
			pr_err("Can't parse: %s\n", buf);
			goto err;
		}

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
				if (errno == ENXIO) {
					struct stat buf;

					if (fstatat(dirfd(map_files_dir), path, &buf, 0))
						goto err_bogus_mapfile;

					if (!S_ISSOCK(buf.st_mode))
						goto err_bogus_mapfile;

					pr_info("Found socket %"PRIu64" mapping @%lx\n", buf.st_ino, start);
					vma_area->vma.status |= VMA_AREA_SOCKET | VMA_AREA_REGULAR;
					vma_area->vm_socket_id = buf.st_ino;
				} else if (errno != ENOENT)
					goto err_bogus_mapfile;
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

		if (vma_area->vma.status != 0) {
			continue;
		} else if (strstr(buf, "[vsyscall]") || strstr(buf, "[vectors]")) {
			vma_area->vma.status |= VMA_AREA_VSYSCALL;
		} else if (strstr(buf, "[vdso]")) {
			vma_area->vma.status |= VMA_AREA_REGULAR;
			if ((vma_area->vma.prot & VDSO_PROT) == VDSO_PROT)
				vma_area->vma.status |= VMA_AREA_VDSO;
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

			if (!S_ISREG(st_buf.st_mode) &&
			    !(S_ISCHR(st_buf.st_mode) && st_buf.st_rdev == DEVZERO)) {
				pr_err("Can't handle non-regular mapping on %d's map %lu\n", pid, start);
				goto err;
			}

			/*
			 * /dev/zero stands for anon-shared mapping
			 * otherwise it's some file mapping.
			 */
			if (is_anon_shmem_map(st_buf.st_dev)) {
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
	}

	vma_area = NULL;
	ret = 0;

err:
	if (smaps)
		fclose(smaps);

	if (map_files_dir)
		closedir(map_files_dir);

	xfree(vma_area);
	return ret;

err_bogus_mapping:
	pr_err("Bogus mapping 0x%"PRIx64"-0x%"PRIx64" (flags: %#x vm_file_fd: %d)\n",
	       vma_area->vma.start, vma_area->vma.end,
	       vma_area->vma.flags, vma_area->vm_file_fd);
	goto err;

err_bogus_mapfile:
	pr_perror("Can't open %d's mapfile link %lx", pid, start);
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

struct opt2flag {
	char *opt;
	unsigned flag;
};

static int do_opt2flag(char *opt, unsigned *flags,
		const struct opt2flag *opts, char *unknown)
{
	int i;
	char *end;

	while (1) {
		end = strchr(opt, ',');
		if (end)
			*end = '\0';

		for (i = 0; opts[i].opt != NULL; i++)
			if (!strcmp(opts[i].opt, opt)) {
				(*flags) |= opts[i].flag;
				break;
			}

		if (opts[i].opt == NULL) {
			if (!unknown) {
				pr_err("Unknown option [%s]\n", opt);
				return -1;
			}

			strcpy(unknown, opt);
			unknown += strlen(opt);
			*unknown = ',';
			unknown++;
		}

		if (!end) {
			if (unknown)
				*unknown = '\0';
			break;
		} else
			opt = end + 1;
	}

	return 0;
}

static int parse_mnt_flags(char *opt, unsigned *flags)
{
	const struct opt2flag mnt_opt2flag[] = {
		{ "rw", 0, },
		{ "ro", MS_RDONLY, },
		{ "nosuid", MS_NOSUID, },
		{ "nodev", MS_NODEV, } ,
		{ "noexec", MS_NOEXEC, },
		{ "noatime", MS_NOATIME, },
		{ "nodiratime", MS_NODIRATIME, },
		{ "relatime", MS_RELATIME, },
		{ },
	};

	return do_opt2flag(opt, flags, mnt_opt2flag, NULL);
}

static int parse_sb_opt(char *opt, unsigned *flags, char *uopt)
{
	const struct opt2flag sb_opt2flag[] = {
		{ "rw", 0, },
		{ "ro", MS_RDONLY, },
		{ "sync", MS_SYNC, },
		{ "dirsync", MS_DIRSYNC, },
		{ "mad", MS_MANDLOCK, },
		{ },
	};

	return do_opt2flag(opt, flags, sb_opt2flag, uopt);
}

static int parse_mnt_opt(char *str, struct mount_info *mi, int *off)
{
	char *istr = str, *end;

	while (1) {
		end = strchr(str, ' ');
		if (!end) {
			pr_err("Error parsing mount options\n");
			return -1;
		}

		*end = '\0';
		if (!strncmp(str, "-", 1))
			break;
		else if (!strncmp(str, "shared:", 7)) {
			mi->flags |= MS_SHARED;
			mi->shared_id = atoi(str + 7);
		} else if (!strncmp(str, "master:", 7)) {
			mi->flags |= MS_SLAVE;
			mi->master_id = atoi(str + 7);
		} else if (!strncmp(str, "propagate_from:", 15)) {
			/* skip */;
		} else if (!strncmp(str, "unbindable", 11))
			mi->flags |= MS_UNBINDABLE;
		else {
			pr_err("Unknown option [%s]\n", str);
			return -1;
		}

		str = end + 1;
	}

	*off = end - istr + 1;
	return 0;
}

static int parse_mountinfo_ent(char *str, struct mount_info *new)
{
	unsigned int kmaj, kmin;
	int ret, n;
	char *opt;
	char *fstype;

	ret = sscanf(str, "%i %i %u:%u %ms %ms %ms %n",
			&new->mnt_id, &new->parent_mnt_id,
			&kmaj, &kmin, &new->root, &new->mountpoint,
			&opt, &n);
	if (ret != 7)
		return -1;

	new->s_dev = MKKDEV(kmaj, kmin);
	new->flags = 0;
	if (parse_mnt_flags(opt, &new->flags))
		return -1;

	free(opt); /* after %ms scanf */

	str += n;
	if (parse_mnt_opt(str, new, &n))
		return -1;

	str += n;
	ret = sscanf(str, "%ms %ms %ms", &fstype, &new->source, &opt);
	if (ret != 3)
		return -1;

	ret = -1;
	new->fstype = find_fstype_by_name(fstype);

	new->options = xmalloc(strlen(opt) + 1);
	if (!new->options)
		goto err;

	if (parse_sb_opt(opt, &new->flags, new->options))
		goto err;

	ret = 0;
err:
	free(opt);
	free(fstype);
	return ret;
}

struct mount_info *parse_mountinfo(pid_t pid)
{
	struct mount_info *list = NULL;
	FILE *f;
	char str[1024];

	snprintf(str, sizeof(str), "/proc/%d/mountinfo", pid);
	f = fopen(str, "r");
	if (!f) {
		pr_perror("Can't open %d mountinfo", pid);
		return NULL;
	}

	while (fgets(str, sizeof(str), f)) {
		struct mount_info *new;
		int ret;

		new = mnt_entry_alloc();
		if (!new)
			goto err;

		new->next = list;
		list = new;

		ret = parse_mountinfo_ent(str, new);
		if (ret < 0) {
			pr_err("Bad format in %d mountinfo\n", pid);
			goto err;
		}

		pr_info("\ttype %s source %s %x %s @ %s flags %x options %s\n",
				new->fstype->name, new->source,
				new->s_dev, new->root, new->mountpoint,
				new->flags, new->options);

		if (new->fstype->parse) {
			ret = new->fstype->parse(new);
			if (ret) {
				pr_err("Failed to parse FS specific data on %s\n",
						new->mountpoint);
				goto err;
			}
		}
	}
out:
	fclose(f);
	return list;

err:
	while (list) {
		struct mount_info *next = list->next;
		mnt_entry_free(list);
		list = next;
	}
	goto out;
}

static char nybble(const char n)
{
	if (n >= '0' && n <= '9')
		return n - '0';
	else if (n >= 'A' && n <= 'F')
		return n - ('A' - 10);
	else if (n >= 'a' && n <= 'f')
		return n - ('a' - 10);
	return 0;
}

static int alloc_fhandle(FhEntry *fh)
{
	fh->n_handle = FH_ENTRY_SIZES__min_entries;
	fh->handle = xmalloc(pb_repeated_size(fh, handle));

	return fh->handle == NULL ? -1 : 0;
}

static void free_fhandle(FhEntry *fh)
{
	xfree(fh->handle);
}

static void parse_fhandle_encoded(char *tok, FhEntry *fh)
{
	char *d = (char *)fh->handle;
	int i = 0;

	memzero(d, pb_repeated_size(fh, handle));

	while (*tok == ' ')
		tok++;

	while (*tok) {
		if (i >= pb_repeated_size(fh, handle))
			break;
		d[i++] = (nybble(tok[0]) << 4) | nybble(tok[1]);
		if (tok[1])
			tok += 2;
		else
			break;
	}
}

#define fdinfo_field(str, field)	!strncmp(str, field":", sizeof(field))

int parse_fdinfo(int fd, int type,
		int (*cb)(union fdinfo_entries *e, void *arg), void *arg)
{
	FILE *f;
	char str[256];
	bool entry_met = false;
	int ret = -1;

	sprintf(str, "/proc/self/fdinfo/%d", fd);
	f = fopen(str, "r");
	if (!f) {
		pr_perror("Can't open fdinfo to parse");
		return -1;
	}

	while (fgets(str, sizeof(str), f)) {
		union fdinfo_entries entry;

		if (fdinfo_field(str, "pos") || fdinfo_field(str, "counter"))
			continue;

		if (fdinfo_field(str, "eventfd-count")) {
			eventfd_file_entry__init(&entry.efd);

			if (type != FD_TYPES__EVENTFD)
				goto parse_err;
			ret = sscanf(str, "eventfd-count: %"PRIx64,
					&entry.efd.counter);
			if (ret != 1)
				goto parse_err;
			ret = cb(&entry, arg);
			if (ret)
				goto out;

			entry_met = true;
			continue;
		}
		if (fdinfo_field(str, "tfd")) {
			eventpoll_tfd_entry__init(&entry.epl);

			if (type != FD_TYPES__EVENTPOLL)
				goto parse_err;
			ret = sscanf(str, "tfd: %d events: %x data: %"PRIx64,
					&entry.epl.tfd, &entry.epl.events, &entry.epl.data);
			if (ret != 3)
				goto parse_err;
			ret = cb(&entry, arg);
			if (ret)
				goto out;

			entry_met = true;
			continue;
		}
		if (fdinfo_field(str, "sigmask")) {
			signalfd_entry__init(&entry.sfd);

			if (type != FD_TYPES__SIGNALFD)
				goto parse_err;
			ret = sscanf(str, "sigmask: %Lx",
					(unsigned long long *)&entry.sfd.sigmask);
			if (ret != 1)
				goto parse_err;
			ret = cb(&entry, arg);
			if (ret)
				goto out;

			entry_met = true;
			continue;
		}
		if (fdinfo_field(str, "fanotify flags")) {
			struct fsnotify_params *p = arg;

			if (type != FD_TYPES__FANOTIFY)
				goto parse_err;

			ret = sscanf(str, "fanotify flags:%x event-flags:%x",
				     &p->faflags, &p->evflags);
			if (ret != 2)
				goto parse_err;
			entry_met = true;
			continue;
		}
		if (fdinfo_field(str, "fanotify ino")) {
			FanotifyInodeMarkEntry ie = FANOTIFY_INODE_MARK_ENTRY__INIT;
			FhEntry f_handle = FH_ENTRY__INIT;
			int hoff;

			if (type != FD_TYPES__FANOTIFY)
				goto parse_err;

			fanotify_mark_entry__init(&entry.ffy);
			ie.f_handle = &f_handle;
			entry.ffy.ie = &ie;

			ret = sscanf(str,
				     "fanotify ino:%"PRIx64" sdev:%x mflags:%x mask:%x ignored_mask:%x "
				     "fhandle-bytes:%x fhandle-type:%x f_handle: %n",
				     &ie.i_ino, &entry.ffy.s_dev,
				     &entry.ffy.mflags, &entry.ffy.mask, &entry.ffy.ignored_mask,
				     &f_handle.bytes, &f_handle.type,
				     &hoff);
			if (ret != 7)
				goto parse_err;

			if (alloc_fhandle(&f_handle)) {
				ret = -1;
				goto out;
			}
			parse_fhandle_encoded(str + hoff, &f_handle);

			entry.ffy.type = MARK_TYPE__INODE;
			ret = cb(&entry, arg);

			free_fhandle(&f_handle);

			if (ret)
				goto out;

			entry_met = true;
			continue;
		}
		if (fdinfo_field(str, "fanotify mnt_id")) {
			FanotifyMountMarkEntry me = FANOTIFY_MOUNT_MARK_ENTRY__INIT;

			if (type != FD_TYPES__FANOTIFY)
				goto parse_err;

			fanotify_mark_entry__init(&entry.ffy);
			entry.ffy.me = &me;

			ret = sscanf(str,
				     "fanotify mnt_id:%x mflags:%x mask:%x ignored_mask:%x",
				     &me.mnt_id, &entry.ffy.mflags,
				     &entry.ffy.mask, &entry.ffy.ignored_mask);
			if (ret != 4)
				goto parse_err;

			entry.ffy.type = MARK_TYPE__MOUNT;
			ret = cb(&entry, arg);
			if (ret)
				goto out;

			entry_met = true;
			continue;
		}
		if (fdinfo_field(str, "inotify wd")) {
			FhEntry f_handle = FH_ENTRY__INIT;
			int hoff;

			inotify_wd_entry__init(&entry.ify);
			entry.ify.f_handle = &f_handle;

			if (type != FD_TYPES__INOTIFY)
				goto parse_err;
			ret = sscanf(str,
					"inotify wd:%x ino:%"PRIx64" sdev:%x "
					"mask:%x ignored_mask:%x "
					"fhandle-bytes:%x fhandle-type:%x "
					"f_handle: %n",
					&entry.ify.wd, &entry.ify.i_ino, &entry.ify.s_dev,
					&entry.ify.mask, &entry.ify.ignored_mask,
					&entry.ify.f_handle->bytes, &entry.ify.f_handle->type,
					&hoff);
			if (ret != 7)
				goto parse_err;

			if (alloc_fhandle(&f_handle)) {
				ret = -1;
				goto out;
			}

			parse_fhandle_encoded(str + hoff, entry.ify.f_handle);

			ret = cb(&entry, arg);

			free_fhandle(&f_handle);

			if (ret)
				goto out;

			entry_met = true;
			continue;
		}
	}

	ret = 0;
	if (entry_met)
		goto out;
	/*
	 * An eventpoll/inotify file may have no target fds set thus
	 * resulting in no tfd: lines in proc. This is normal.
	 */
	if (type == FD_TYPES__EVENTPOLL || type == FD_TYPES__INOTIFY)
		goto out;

	pr_err("No records of type %d found in fdinfo file\n", type);
parse_err:
	ret = -1;
	pr_perror("%s: error parsing [%s] for %d", __func__, str, type);
out:
	fclose(f);
	return ret;
}

static int parse_file_lock_buf(char *buf, struct file_lock *fl,
				bool is_blocked)
{
	int  num;

	if (is_blocked) {
		num = sscanf(buf, "%lld: -> %s %s %s %d %x:%x:%ld %lld %s",
			&fl->fl_id, fl->fl_flag, fl->fl_type, fl->fl_option,
			&fl->fl_owner, &fl->maj, &fl->min, &fl->i_no,
			&fl->start, fl->end);
	} else {
		num = sscanf(buf, "%lld:%s %s %s %d %x:%x:%ld %lld %s",
			&fl->fl_id, fl->fl_flag, fl->fl_type, fl->fl_option,
			&fl->fl_owner, &fl->maj, &fl->min, &fl->i_no,
			&fl->start, fl->end);
	}

	if (num < 10) {
		pr_err("Invalid file lock info (%d): %s", num, buf);
		return -1;
	}

	return 0;
}

int parse_file_locks(void)
{
	struct file_lock *fl;

	FILE	*fl_locks;
	int	ret = 0;
	bool	is_blocked;

	fl_locks = fopen("/proc/locks", "r");
	if (!fl_locks) {
		pr_perror("Can't open file locks file!");
		return -1;
	}

	while (fgets(buf, BUF_SIZE, fl_locks)) {
		is_blocked = strstr(buf, "->") != NULL;

		fl = alloc_file_lock();
		if (!fl) {
			pr_perror("Alloc file lock failed!");
			ret = -1;
			goto err;
		}

		if (parse_file_lock_buf(buf, fl, is_blocked)) {
			xfree(fl);
			ret = -1;
			goto err;
		}

		if (!pid_in_pstree(fl->fl_owner)) {
			/*
			 * We only care about tasks which are taken
			 * into dump, so we only collect file locks
			 * belong to these tasks.
			 */
			xfree(fl);
			continue;
		}

		if (is_blocked) {
			/*
			 * Here the task is in the pstree.
			 * If it is blocked on a flock, when we try to
			 * ptrace-seize it, the kernel will unblock task
			 * from flock and will stop it in another place.
			 * So in dumping, a blocked file lock should never
			 * be here.
			 */
			pr_perror("We have a blocked file lock!");
			ret = -1;
			xfree(fl);
			goto err;
		}

		pr_info("lockinfo: %lld:%s %s %s %d %02x:%02x:%ld %lld %s\n",
			fl->fl_id, fl->fl_flag, fl->fl_type, fl->fl_option,
			fl->fl_owner, fl->maj, fl->min, fl->i_no,
			fl->start, fl->end);

		list_add_tail(&fl->list, &file_lock_list);
	}

err:
	fclose(fl_locks);
	return ret;
}

int parse_posix_timers(pid_t pid, struct proc_posix_timers_stat *args)
{
	int ret = 0;
	int pid_t;

	FILE * file;

	char sigpid[7];
	char tidpid[4];

	struct proc_posix_timer *timer = NULL;

	INIT_LIST_HEAD(&args->timers);
	args->timer_n = 0;

	file = fopen_proc(pid, "timers");
	if (file == NULL) {
		pr_perror("Can't open posix timers file!");
		return -1;
	}

	while (1) {
		timer = xzalloc(sizeof(struct proc_posix_timer));
		if (timer == NULL)
			goto err;

		ret = fscanf(file, "ID: %ld\n"
				   "signal: %d/%p\n"
				   "notify: %6[a-z]/%3[a-z].%d\n"
				   "ClockID: %d\n",
				&timer->spt.it_id,
				&timer->spt.si_signo, &timer->spt.sival_ptr,
				sigpid, tidpid, &pid_t,
				&timer->spt.clock_id);
		if (ret != 7) {
			ret = 0;
			xfree(timer);
			if (feof(file))
				goto out;
			goto err;
		}

		if ( tidpid[0] == 't') {
			timer->spt.it_sigev_notify = SIGEV_THREAD_ID;
		} else {
			switch (sigpid[0]) {
				case 's' :
					timer->spt.it_sigev_notify = SIGEV_SIGNAL;
					break;
				case 't' :
					timer->spt.it_sigev_notify = SIGEV_THREAD;
					break;
				default :
					timer->spt.it_sigev_notify = SIGEV_NONE;
					break;
			}
		}

		list_add(&timer->list, &args->timers);
		timer = NULL;
		args->timer_n++;
	}
err:
	while (!list_empty(&args->timers)) {
		timer = list_first_entry(&args->timers, struct proc_posix_timer, list);
		list_del(&timer->list);
		xfree(timer);
	}
	pr_perror("Parse error in posix timers proc file!");
	ret = -1;
out:
	fclose(file);
	return ret;
}

int parse_threads(int pid, struct pid **_t, int *_n)
{
	struct dirent *de;
	DIR *dir;
	struct pid *t = NULL;
	int nr = 1;

	if (*_t)
		t = *_t;

	dir = opendir_proc(pid, "task");
	if (!dir)
		return -1;

	while ((de = readdir(dir))) {
		struct pid *tmp;

		/* We expect numbers only here */
		if (de->d_name[0] == '.')
			continue;

		if (*_t == NULL) {
			tmp = xrealloc(t, nr * sizeof(struct pid));
			if (!tmp) {
				xfree(t);
				return -1;
			}
			t = tmp;
			t[nr - 1].virt = -1;
		}
		t[nr - 1].real = atoi(de->d_name);
		nr++;
	}

	closedir(dir);

	if (*_t == NULL) {
		*_t = t;
		*_n = nr - 1;
	} else
		BUG_ON(nr - 1 != *_n);

	return 0;
}
