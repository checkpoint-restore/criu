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

#include "types.h"
#include "list.h"
#include "util.h"
#include "crtools.h"
#include "mount.h"

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

int parse_smaps(pid_t pid, struct list_head *vma_area_list, bool use_map_files)
{
	struct vma_area *vma_area = NULL;
	u64 start, end, pgoff;
	unsigned long ino;
	char r, w, x, s;
	int dev_maj, dev_min;
	int ret = -1, nr = 0;

	DIR *map_files_dir = NULL;
	FILE *smaps = NULL;

	smaps = fopen_proc(pid, "smaps");
	if (!smaps)
		goto err;

	if (use_map_files) {
		map_files_dir = opendir_proc(pid, "map_files");
		if (!map_files_dir) /* old kernel? */
			goto err;
	}

	while (fgets(buf, BUF_SIZE, smaps)) {
		int num;
		char file_path[6];

		if (!is_vma_range_fmt(buf)) {
			if (!strncmp(buf, "Nonlinear", 9)) {
				BUG_ON(!vma_area);
				pr_err("Nonlinear mapping found %016lx-%016lx\n",
				       vma_area->vma.start, vma_area->vma.end);
				/*
				 * VMA is already on list and will be
				 * freed later as list get destroyed.
				 */
				vma_area = NULL;
				goto err;
			} else
				continue;
		}

		vma_area = alloc_vma_area();
		if (!vma_area)
			goto err;

		memset(file_path, 0, 6);
		num = sscanf(buf, "%lx-%lx %c%c%c%c %lx %02x:%02x %lu %5s",
			     &start, &end, &r, &w, &x, &s, &pgoff, &dev_maj,
			     &dev_min, &ino, file_path);
		if (num < 10) {
			pr_err("Can't parse: %s", buf);
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

		if (strstr(buf, "[vsyscall]")) {
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
	if (smaps)
		fclose(smaps);

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
			pr_err("Error parsing mount options");
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

	new->fstype = find_fstype_by_name(fstype);
	free(fstype);

	new->options = xmalloc(strlen(opt));
	if (!new->options)
		return -1;

	if (parse_sb_opt(opt, &new->flags, new->options))
		return -1;

	free(opt);

	return 0;
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

		new = xmalloc(sizeof(*new));
		if (!new)
			goto err;

		mnt_entry_init(new);

		ret = parse_mountinfo_ent(str, new);
		if (ret < 0) {
			pr_err("Bad format in %d mountinfo\n", pid);
			goto err;
		}

		pr_info("\ttype %s source %s %x %s @ %s flags %x options %s\n",
				new->fstype->name, new->source,
				new->s_dev, new->root, new->mountpoint,
				new->flags, new->options);

		new->next = list;
		list = new;
	}
out:
	fclose(f);
	return list;

err:
	while (list) {
		struct mount_info *next = list->next;
		xfree(list);
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

	sprintf(str, "/proc/self/fdinfo/%d", fd);
	f = fopen(str, "r");
	if (!f) {
		pr_perror("Can't open fdinfo to parse");
		return -1;
	}

	while (fgets(str, sizeof(str), f)) {
		int ret;
		union fdinfo_entries entry;

		if (fdinfo_field(str, "pos") || fdinfo_field(str, "counter"))
			continue;

		if (fdinfo_field(str, "eventfd-count")) {
			eventfd_file_entry__init(&entry.efd);

			if (type != FD_TYPES__EVENTFD)
				goto parse_err;
			ret = sscanf(str, "eventfd-count: %lx",
					&entry.efd.counter);
			if (ret != 1)
				goto parse_err;
			ret = cb(&entry, arg);
			if (ret)
				return ret;

			entry_met = true;
			continue;
		}
		if (fdinfo_field(str, "tfd")) {
			eventpoll_tfd_entry__init(&entry.epl);

			if (type != FD_TYPES__EVENTPOLL)
				goto parse_err;
			ret = sscanf(str, "tfd: %d events: %x data: %lx",
					&entry.epl.tfd, &entry.epl.events, &entry.epl.data);
			if (ret != 3)
				goto parse_err;
			ret = cb(&entry, arg);
			if (ret)
				return ret;

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
				return ret;

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
					"inotify wd: %8d ino: %16lx sdev: %8x "
					"mask: %8x ignored_mask: %8x "
					"fhandle-bytes: %8x fhandle-type: %8x "
					"f_handle: %n",
					&entry.ify.wd, &entry.ify.i_ino, &entry.ify.s_dev,
					&entry.ify.mask, &entry.ify.ignored_mask,
					&entry.ify.f_handle->bytes, &entry.ify.f_handle->type,
					&hoff);
			if (ret != 7)
				goto parse_err;

			f_handle.n_handle = FH_ENTRY_SIZES__min_entries;
			f_handle.handle = xmalloc(pb_repeated_size(&f_handle, handle));
			if (!f_handle.handle)
				return -1;

			parse_fhandle_encoded(str + hoff, entry.ify.f_handle);

			ret = cb(&entry, arg);

			xfree(f_handle.handle);

			if (ret)
				return ret;

			entry_met = true;
			continue;
		}
	}

	fclose(f);

	if (entry_met)
		return 0;
	/*
	 * An eventpoll file may have no target fds set thus
	 * resulting in no tfd: lines in proc. This is normal.
	 */
	if (type == FD_TYPES__EVENTPOLL)
		return 0;

	pr_err("No records of type %d found in fdinfo file\n", type);
parse_err:
	pr_perror("%s: error parsing [%s] for %d\n", __func__, str, type);
	return -1;
}
