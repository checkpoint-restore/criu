#include <unistd.h>
#include <sys/stat.h>

#include "proc_parse.h"
#include "autofs.h"
#include "util.h"
#include "mount.h"
#include "pstree.h"
#include "namespaces.h"
#include "protobuf.h"

#include "images/autofs.pb-c.h"

#define AUTOFS_OPT_UNKNOWN	INT_MIN

#define AUTOFS_MODE_DIRECT	0
#define AUTOFS_MODE_INDIRECT	1
#define AUTOFS_MODE_OFFSET	2

#define AUTOFS_CATATONIC_FD	-1

struct autofs_pipe_s {
	struct list_head list;
	unsigned long inode;
};

struct list_head autofs_pipes = LIST_HEAD_INIT(autofs_pipes);

bool is_autofs_pipe(unsigned long inode)
{
	struct autofs_pipe_s *p;

	list_for_each_entry(p, &autofs_pipes, list) {
		if (p->inode == inode)
			return true;
	}
	return false;
}

static int autofs_gather_pipe(unsigned long inode)
{
	struct autofs_pipe_s *pipe;

	pipe = xmalloc(sizeof(*pipe));
	if (!pipe)
		return -1;
	pipe->inode = inode;
	list_add_tail(&pipe->list, &autofs_pipes);
	return 0;
}

int autofs_parse(struct mount_info *pm)
{
	long pipe_ino = AUTOFS_OPT_UNKNOWN;
	char **opts;
	int nr_opts, i;

	split(pm->options, ',', &opts, &nr_opts);
	if (!opts)
		return -1;
	for (i = 0; i < nr_opts; i++) {
		if (!strncmp(opts[i], "pipe_ino=", strlen("pipe_ino=")))
			pipe_ino = atoi(opts[i] + strlen("pipe_ino="));
	}
	for (i = 0; i < nr_opts; i++)
		xfree(opts[i]);
	free(opts);

	if (pipe_ino == AUTOFS_OPT_UNKNOWN) {
		pr_err("Failed to find pipe_ino option (old kernel?)\n");
		return -1;
	}

	return autofs_gather_pipe(pipe_ino);
}

static int autofs_check_fd_stat(struct stat *stat, int prgp, int fd,
				long ino, int *mode)
{
	struct fdinfo_common fdinfo;

	if (!S_ISFIFO(stat->st_mode))
		return 0;
	if (stat->st_ino != ino)
		return 0;
	if (parse_fdinfo_pid(prgp, fd, FD_TYPES__UND, NULL, &fdinfo))
		return -1;

	*mode = fdinfo.flags & O_WRONLY;
	return 1;
}

static int autofs_kernel_pipe_alive(int pgrp, int fd, int ino)
{
	struct stat buf;
	char *path;
	int ret, fd_mode;

	path = xsprintf("/proc/%d/fd/%d", pgrp, fd);
	if (!path)
		return -1;

	if (stat(path, &buf) < 0) {
		if (errno == ENOENT)
			return 0;
		pr_perror("Failed to stat %s", path);
		return -1;
	}

	xfree(path);

	ret = autofs_check_fd_stat(&buf, pgrp, fd, ino, &fd_mode);
	if (ret <= 0)
		return ret;

	return O_WRONLY == fd_mode;
}

static int autofs_find_pipe_read_end(int pgrp, long ino, int *read_fd)
{
	DIR *dir;
	struct dirent *de;
	int ret = -1;

	dir = opendir_proc(pgrp, "fd");
	if (dir == NULL)
		return -1;

	*read_fd = -1;

	while ((de = readdir(dir))) {
		struct stat buf;
		int found, mode, fd;

		if (dir_dots(de))
			continue;

		if (fstatat(dirfd(dir), de->d_name, &buf, 0) < 0) {
			pr_perror("Failed to fstatat");
			break;
		}

		fd = atoi(de->d_name);

		found = autofs_check_fd_stat(&buf, pgrp, fd, ino, &mode);
		if (found < 0)
			break;
		if (found && (mode == O_RDONLY)) {
			*read_fd = fd;
			ret = 0;
			break;
		}
	}

	closedir(dir);
	close_pid_proc();

	return ret;
}

static int autofs_find_read_fd(int pgrp, long pipe_ino)
{
	int read_fd, fd;

	/* We need to find read end and make sure, that it's empty */
	if (autofs_find_pipe_read_end(pgrp, pipe_ino, &read_fd) < 0) {
		pr_err("Failed to find read pipe fd (ino %ld) "
			"in process %d\n", pipe_ino, pgrp);
		return -1;
	}

	if (read_fd == -1) {
		pr_err("Master %d doesn't have a read end of the pipe with "
			"inode %ld opened\n", pgrp, pipe_ino);
		pr_err("Abandoned mount or control was delegated to child?\n");
		return -1;
	}

	/* Let's check, that read end is empty */
	fd = open_proc(pgrp, "fd/%d", read_fd);
	if (fd < 0)
		return -1;

	if (fd_has_data(fd)) {
		pr_err("Process %d autofs pipe fd %d is not empty.\n", pgrp,
				read_fd);
		pr_err("Try again later.\n");
		return -1;
	}
	close(fd);
	return read_fd;
}

static int parse_options(char *options, AutofsEntry *entry, long *pipe_ino)
{
	char **opts;
	int nr_opts, i;

	entry->fd = AUTOFS_OPT_UNKNOWN;
	entry->timeout = AUTOFS_OPT_UNKNOWN;
	entry->minproto = AUTOFS_OPT_UNKNOWN;
	entry->maxproto = AUTOFS_OPT_UNKNOWN;
	entry->mode = AUTOFS_OPT_UNKNOWN;
	entry->pgrp = AUTOFS_OPT_UNKNOWN;
	entry->uid = AUTOFS_OPT_UNKNOWN;
	entry->gid = AUTOFS_OPT_UNKNOWN;
	*pipe_ino = AUTOFS_OPT_UNKNOWN;

	split(options, ',', &opts, &nr_opts);
	if (!opts)
		return -1;

	for (i = 0; i < nr_opts; i++) {
		char *opt = opts[i];

		if (!strncmp(opt, "fd=", strlen("fd=")))
			entry->fd = atoi(opt + strlen("fd="));
		else if (!strncmp(opt, "pipe_ino=", strlen("pipe_ino=")))
			*pipe_ino = atoi(opt + strlen("pipe_ino="));
		else if (!strncmp(opt, "pgrp=", strlen("pgrp=")))
			entry->pgrp = atoi(opt + strlen("pgrp="));
		else if (!strncmp(opt, "timeout=", strlen("timeout=")))
			entry->timeout = atoi(opt + strlen("timeout="));
		else if (!strncmp(opt, "minproto=", strlen("minproto=")))
			entry->minproto = atoi(opt + strlen("minproto="));
		else if (!strncmp(opt, "maxproto=", strlen("maxproto=")))
			entry->maxproto = atoi(opt + strlen("maxproto="));
		else if (!strcmp(opt, "indirect"))
			entry->mode = AUTOFS_MODE_INDIRECT;
		else if (!strcmp(opt, "offset"))
			entry->mode = AUTOFS_MODE_OFFSET;
		else if (!strcmp(opt, "direct"))
			entry->mode = AUTOFS_MODE_DIRECT;
		else if (!strncmp(opt, "uid=", strlen("uid=")))
			entry->uid = atoi(opt + strlen("uid="));
		else if (!strncmp(opt, "gid=", strlen("gid=")))
			entry->gid = atoi(opt + strlen("gid="));
	}

	for (i = 0; i < nr_opts; i++)
		xfree(opts[i]);
	xfree(opts);

	if (entry->fd == AUTOFS_OPT_UNKNOWN) {
		pr_err("Failed to find fd option\n");
		return -1;
	}
	if (entry->pgrp == AUTOFS_OPT_UNKNOWN) {
		pr_err("Failed to find pgrp option\n");
		return -1;
	}
	if (entry->timeout == AUTOFS_OPT_UNKNOWN) {
		pr_err("Failed to find timeout option\n");
		return -1;
	}
	if (entry->minproto == AUTOFS_OPT_UNKNOWN) {
		pr_err("Failed to find minproto option\n");
		return -1;
	}
	if (entry->maxproto == AUTOFS_OPT_UNKNOWN) {
		pr_err("Failed to find maxproto option\n");
		return -1;
	}
	if (entry->mode == AUTOFS_OPT_UNKNOWN) {
		pr_err("Failed to find mode (direct,indirect,offset) option\n");
		return -1;
	}
	if (*pipe_ino == AUTOFS_OPT_UNKNOWN) {
		pr_err("Failed to find pipe_ino option (old kernel?)\n");
		return -1;
	}

	return 0;
}

static int autofs_create_entry(struct mount_info *pm, AutofsEntry *entry)
{
	long pipe_ino;

	if (parse_options(pm->options, entry, &pipe_ino))
		return -1;

	if (entry->uid != AUTOFS_OPT_UNKNOWN)
		entry->has_uid = true;
	if (entry->gid != AUTOFS_OPT_UNKNOWN)
		entry->has_gid = true;

	if (entry->fd != AUTOFS_CATATONIC_FD) {
		int found, read_fd;

		read_fd = autofs_find_read_fd(entry->pgrp, pipe_ino);
		if (read_fd < 0)
			return -1;

		/* Let' check whether write end is still open */
		found = autofs_kernel_pipe_alive(entry->pgrp, entry->fd, pipe_ino);
		if (found < 0) {
			pr_err("Failed to check fd %d in process %d\n",
					entry->fd, entry->pgrp);
			return -1;
		}
		/* Write end is absent. we need to carry read end to restore. */
		if (!found) {
			entry->has_read_fd = true;
			entry->read_fd = read_fd;
		}

		/* We need to get virtual pgrp to restore mount */
		entry->pgrp = pid_to_virt(entry->pgrp);
		if (!entry->pgrp) {
			pr_err("failed to find pstree item with pid %d\n",
					entry->pgrp);
			pr_err("Non-catatonic mount without master?\n");
			return -1;
		}
	}
	return 0;
}

static int autofs_dump_entry(struct mount_info *pm, AutofsEntry *entry)
{
	struct cr_img *img;
	int ret = -1;

	img = open_image(CR_FD_AUTOFS, O_DUMP, pm->s_dev);
	if (img)
		ret = pb_write_one(img, entry, PB_AUTOFS);
	close_image(img);
	return ret;
}


int autofs_dump(struct mount_info *pm)
{
	AutofsEntry *entry;

	entry = xmalloc(sizeof(*entry));
	if (!entry)
		return -1;
	autofs_entry__init(entry);

	if (autofs_create_entry(pm, entry))
		return -1;

	return autofs_dump_entry(pm, entry);
}
