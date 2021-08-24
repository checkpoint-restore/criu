#include <unistd.h>
#include <sys/stat.h>
#include <stdarg.h>
#include <sys/mount.h>
#include <sys/wait.h>

#include "int.h"
#include "fdinfo.h"
#include "autofs.h"
#include "rst-malloc.h"
#include "mount.h"
#include "pstree.h"
#include "namespaces.h"
#include "protobuf.h"
#include "pipes.h"
#include "crtools.h"
#include "util.h"

#include "images/autofs.pb-c.h"

#define AUTOFS_OPT_UNKNOWN INT_MIN

#define AUTOFS_MODE_DIRECT   0
#define AUTOFS_MODE_INDIRECT 1
#define AUTOFS_MODE_OFFSET   2

#define AUTOFS_CATATONIC_FD -1

static int autofs_mnt_open(const char *mnt_path, dev_t devid);

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
	int nr_opts, i, ret;

	split(pm->options, ',', &opts, &nr_opts);
	if (!opts)
		return -1;

	for (i = 0; i < nr_opts; i++) {
		if (!strncmp(opts[i], "pipe_ino=", strlen("pipe_ino=")))
			if (xatol(opts[i] + strlen("pipe_ino="), &pipe_ino)) {
				pr_err("pipe_ino (%s) mount option parse failed\n", opts[i] + strlen("pipe_ino="));
				ret = -1;
				goto free;
			}
	}

	/*
	 * We must inform user about bug if pipe_ino is greater than UINT32_MAX,
	 * because it means that something changed in Linux Kernel virtual fs
	 * inode numbers generation mechanism. What we have at the moment:
	 * 1. struct inode i_ino field (include/linux/fs.h in Linux kernel)
	 * has unsigned long type.
	 * 2. get_next_ino() function (fs/inode.c), that used for generating inode
	 * numbers on virtual filesystems (pipefs, debugfs for instance)
	 * has unsigned int as return type.
	 * So, it means that ATM it is safe to keep uint32 type for pipe_id field
	 * in pipe-data.proto.
	 */
	if (pipe_ino > UINT32_MAX) {
		pr_err("overflow: pipe_ino > UINT32_MAX\n");
		ret = -1;
		goto free;
	}

	if (pipe_ino == AUTOFS_OPT_UNKNOWN) {
		pr_warn("Failed to find pipe_ino option (old kernel?)\n");
		ret = 0;
		goto free;
	}

	ret = autofs_gather_pipe(pipe_ino);

free:
	for (i = 0; i < nr_opts; i++)
		xfree(opts[i]);
	xfree(opts);

	return ret;
}

static int autofs_check_fd_stat(struct stat *stat, int prgp, int fd, long ino, int *mode)
{
	struct fdinfo_common fdinfo;

	if (!S_ISFIFO(stat->st_mode))
		return 0;
	if (stat->st_ino != ino)
		return 0;
	if (parse_fdinfo_pid(prgp, fd, FD_TYPES__UND, &fdinfo))
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
		if (errno == ENOENT) {
			xfree(path);
			return 0;
		}
		pr_perror("Failed to stat %s", path);
		xfree(path);
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
			goto out;
		}

		ret = xatoi(de->d_name, &fd);
		if (ret)
			goto out;

		found = autofs_check_fd_stat(&buf, pgrp, fd, ino, &mode);
		if (found < 0)
			goto out;
		if (found && (mode == O_RDONLY)) {
			*read_fd = fd;
			break;
		}
	}

	ret = 0;

out:
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
		       "in process %d\n",
		       pipe_ino, pgrp);
		return -1;
	}

	if (read_fd == -1) {
		pr_err("Master %d doesn't have a read end of the pipe with "
		       "inode %ld opened\n",
		       pgrp, pipe_ino);
		pr_err("Abandoned mount or control was delegated to child?\n");
		return -ENOENT;
	}

	/* Let's check, that read end is empty */
	fd = open_proc(pgrp, "fd/%d", read_fd);
	if (fd < 0)
		return -1;

	if (fd_has_data(fd)) {
		pr_err("Process %d autofs pipe fd %d is not empty.\n", pgrp, read_fd);
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
	int parse_error = 0;

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
		int err = 0;

		if (!strncmp(opt, "fd=", strlen("fd=")))
			err = xatoi(opt + strlen("fd="), &entry->fd);
		else if (!strncmp(opt, "pipe_ino=", strlen("pipe_ino=")))
			err = xatol(opt + strlen("pipe_ino="), pipe_ino);
		else if (!strncmp(opt, "pgrp=", strlen("pgrp=")))
			err = xatoi(opt + strlen("pgrp="), &entry->pgrp);
		else if (!strncmp(opt, "timeout=", strlen("timeout=")))
			err = xatoi(opt + strlen("timeout="), &entry->timeout);
		else if (!strncmp(opt, "minproto=", strlen("minproto=")))
			err = xatoi(opt + strlen("minproto="), &entry->minproto);
		else if (!strncmp(opt, "maxproto=", strlen("maxproto=")))
			err = xatoi(opt + strlen("maxproto="), &entry->maxproto);
		else if (!strcmp(opt, "indirect"))
			entry->mode = AUTOFS_MODE_INDIRECT;
		else if (!strcmp(opt, "offset"))
			entry->mode = AUTOFS_MODE_OFFSET;
		else if (!strcmp(opt, "direct"))
			entry->mode = AUTOFS_MODE_DIRECT;
		else if (!strncmp(opt, "uid=", strlen("uid=")))
			err = xatoi(opt + strlen("uid="), &entry->uid);
		else if (!strncmp(opt, "gid=", strlen("gid=")))
			err = xatoi(opt + strlen("gid="), &entry->gid);

		if (err) {
			parse_error = 1;
			break;
		}
	}

	for (i = 0; i < nr_opts; i++)
		xfree(opts[i]);
	xfree(opts);

	if (parse_error)
		return -1;

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

static int autofs_revisit_options(struct mount_info *pm)
{
	FILE *f;
	char *buf;
	int ret = -ENOMEM;

	buf = xmalloc(1024);
	if (!buf) {
		return -ENOMEM;
	}

	f = fopen_proc(getpid(), "mountinfo");
	if (!f)
		goto free_str;

	while (fgets(buf, 1024, f)) {
		int mnt_id = -1;
		char *str = buf;
		char *token;

		/* Removing '/n' */
		str[strlen(str) - 1] = '\0';

		while ((token = strsep(&str, " ")) != NULL) {
			if (mnt_id == -1) {
				ret = xatoi(token, &mnt_id);
				if (ret)
					goto close_proc;
				if (mnt_id != pm->mnt_id)
					break;
			} else if (strstr(token, "pipe_ino=")) {
				ret = 0;
				free(pm->options);

				pm->options = xstrdup(token);
				if (!pm->options)
					pr_err("failed to duplicate string\n");
				else
					ret = 0;
				goto close_proc;
			}
		}
	}

	pr_err("failed to find autofs mount with mnt_id %d\n", pm->mnt_id);
	ret = -ENOENT;

close_proc:
	fclose(f);
free_str:
	free(buf);
	return ret;
}

/*
 * To access the mount point we have to set proper mount namespace.
 * But, unfortunately, we have to set proper pid namespace as well,
 * because otherwise autofs driver won't find the autofs master.
 */
static int access_autofs_mount(struct mount_info *pm)
{
	const char *mnt_path = pm->mountpoint + 1;
	dev_t dev_id = pm->s_dev;
	int new_pid_ns = -1, old_pid_ns = -1;
	int old_mnt_ns, old_cwd_fd;
	int autofs_mnt;
	int err = -1;
	int pid, status;

	/*
	 * To be able to set proper pid namespace, we must open fd before
	 * switching to the mount namespace.
	 * The same applies to pid namespace fd to restore back.
	 */
	new_pid_ns = open_proc(pm->nsid->ns_pid, "ns/pid");
	if (new_pid_ns < 0)
		return -1;

	old_pid_ns = open_proc(PROC_SELF, "ns/pid");
	if (old_pid_ns < 0)
		goto close_new_pid_ns;

	if (switch_mnt_ns(pm->nsid->ns_pid, &old_mnt_ns, &old_cwd_fd)) {
		pr_err("failed to switch to mount namespace\n");
		goto close_old_pid_ns;
	}

	err = restore_ns(new_pid_ns, &pid_ns_desc);
	new_pid_ns = -1;
	if (err) {
		pr_err("failed to restore pid namespace\n");
		goto restore_mnt_ns;
	}

	autofs_mnt = autofs_mnt_open(mnt_path, dev_id);
	if (autofs_mnt < 0)
		goto restore_pid_ns;

	pid = fork();
	switch (pid) {
	case -1:
		pr_err("failed to fork\n");
		goto close_autofs_mnt;
	case 0:
		/* We don't care about results.
			 * All we need is to "touch" */
		/* coverity[check_return] */
		openat(autofs_mnt, mnt_path, O_RDONLY | O_NONBLOCK | O_DIRECTORY);
		_exit(0);
	}
	/* Here we also don't care about results */
	waitpid(pid, &status, 0);

	err = autofs_revisit_options(pm);

close_autofs_mnt:
	close(autofs_mnt);
restore_pid_ns:
	if (restore_ns(old_pid_ns, &pid_ns_desc)) {
		pr_err("failed to restore pid namespace\n");
		err = -1;
	}
	old_pid_ns = -1;
restore_mnt_ns:
	if (restore_mnt_ns(old_mnt_ns, &old_cwd_fd)) {
		pr_err("failed to restore mount namespace\n");
		err = -1;
	}
close_old_pid_ns:
	if (old_pid_ns >= 0)
		close(old_pid_ns);
close_new_pid_ns:
	if (new_pid_ns >= 0)
		close(new_pid_ns);
	return err;
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
		int found, read_fd, virt_pgrp;

		read_fd = autofs_find_read_fd(entry->pgrp, pipe_ino);
		if (read_fd < 0) {
			if (read_fd != -ENOENT)
				return -1;

			/* Ok, our read end doesn't exist.
			 * There can be a case, when mount looks normal, but
			 * it's a "hidden" or "abandoned" catatonic mount in
			 * reality.
			 * This can happen if:
			 * 1) autofs master process has exited without switching
			 * the mount to catatonic mode (or was killed).
			 * 2) mount point was unmounted, but not propagated to
			 * nested mount namespace with private mounts.
			 * We can try handle these cases by accessing the mount
			 * point. If it's catatonic, it will update it's
			 * options, then we can read them again and dump it.
			 */
			if (access_autofs_mount(pm)) {
				pr_err("failed to access autofs %s\n", pm->mountpoint + 1);
				return -1;
			}
			if (parse_options(pm->options, entry, &pipe_ino))
				return -1;
			if (entry->fd == AUTOFS_CATATONIC_FD)
				return 0;
			pr_err("Autofs %d is alive, but unreachable.\n", pm->mnt_id);
			return -1;
		}

		/* Let' check whether write end is still open */
		found = autofs_kernel_pipe_alive(entry->pgrp, entry->fd, pipe_ino);
		if (found < 0) {
			pr_err("Failed to check fd %d in process %d\n", entry->fd, entry->pgrp);
			return -1;
		}
		/* Write end is absent. we need to carry read end to restore. */
		if (!found) {
			entry->has_read_fd = true;
			entry->read_fd = read_fd;
		}

		/* We need to get virtual pgrp to restore mount */
		virt_pgrp = pid_to_virt(entry->pgrp);
		if (!virt_pgrp) {
			pr_err("failed to find pstree item with pid %d\n", entry->pgrp);
			pr_err("Non-catatonic mount without master?\n");
			return -1;
		}
		entry->pgrp = virt_pgrp;
	}
	return 0;
}

static int autofs_dump_entry(struct mount_info *pm, AutofsEntry *entry)
{
	struct cr_img *img;
	int ret = -1;

	img = open_image(CR_FD_AUTOFS, O_DUMP, pm->s_dev);
	if (img) {
		ret = pb_write_one(img, entry, PB_AUTOFS);
		close_image(img);
	}
	return ret;
}

int autofs_dump(struct mount_info *pm)
{
	AutofsEntry *entry;
	int err;

	entry = xmalloc(sizeof(*entry));
	if (!entry)
		return -1;
	autofs_entry__init(entry);

	err = autofs_create_entry(pm, entry);
	if (err)
		goto free_entry;

	err = autofs_dump_entry(pm, entry);

free_entry:
	free(entry);
	return err < 0 ? err : 0;
}

typedef struct autofs_info_s {
	struct pipe_info pi;
	AutofsEntry *entry;
	char *mnt_path;
	dev_t mnt_dev;
	struct mount_info *mi;
	struct pprep_head ph;
} autofs_info_t;

static int dup_pipe_info(struct pipe_info *pi, int flags, struct file_desc_ops *ops)
{
	struct pipe_info *new;
	PipeEntry *pe;

	new = shmalloc(sizeof(*new));
	if (!new)
		return -1;

	pe = shmalloc(sizeof(*pe));
	if (!pe)
		return -1;

	pe->id = pi->pe->id;
	pe->pipe_id = pi->pe->pipe_id;
	pe->fown = pi->pe->fown;
	pe->flags = flags;

	if (collect_one_pipe_ops(new, &pe->base, ops) < 0) {
		pr_err("Failed to add pipe info for write end\n");
		return -1;
	}

	return 0;
}

static int autofs_dup_pipe(struct pstree_item *task, struct fdinfo_list_entry *ple, int new_fd)
{
	struct pipe_info *pi = container_of(ple->desc, struct pipe_info, d);
	unsigned flags = O_WRONLY;

	new_fd = find_unused_fd(task, new_fd);

	if (dup_pipe_info(pi, flags, pi->d.ops) < 0) {
		pr_err("Failed to dup pipe entry ID %#x PIPE_ID %#x\n", pi->pe->id, pi->pe->pipe_id);
		return -1;
	}

	if (dup_fle(task, ple, new_fd, flags) < 0) {
		pr_err("Failed to add fd %d to process %d\n", new_fd, vpid(task));
		return -1;
	}

	pr_info("autofs: added pipe fd %d, flags %#x to %d\n", new_fd, flags, vpid(task));
	return new_fd;
}

static int autofs_ioctl(const char *path, int fd, int cmd, const void *param)
{
	int err;

	err = ioctl(fd, cmd, param);
	if (err)
		pr_perror("%s ioctl failed", path);

	return err;
}

static int autofs_dev_ioctl(int cmd, struct autofs_dev_ioctl *param)
{
	char *path = "/dev/" AUTOFS_DEVICE_NAME;
	int fd, err;

	fd = open(path, O_RDONLY);
	if (fd == -1) {
		pr_perror("failed to open %s", path);
		return -1;
	}

	err = autofs_ioctl(path, fd, cmd, param);

	close(fd);
	return err;
}

static int autofs_mnt_make_catatonic(const char *mnt_path, int mnt_fd)
{
	pr_info("%s: set %s catatonic\n", __func__, mnt_path);
	return autofs_ioctl(mnt_path, mnt_fd, AUTOFS_IOC_CATATONIC, NULL);
}

static int autofs_mnt_set_timeout(time_t timeout, const char *mnt_path, int mnt_fd)
{
	pr_info("%s: set timeout %ld for %s\n", __func__, timeout, mnt_path);
	return autofs_ioctl(mnt_path, mnt_fd, AUTOFS_IOC_SETTIMEOUT, &timeout);
}

static int autofs_mnt_set_pipefd(const autofs_info_t *i, int mnt_fd)
{
	struct autofs_dev_ioctl param;

	/* Restore pipe and pgrp only for non-catatonic mounts */
	if (i->entry->fd == AUTOFS_CATATONIC_FD)
		return 0;

	pr_info("%s: set pipe fd %d (pgrp %d) for mount %s\n", __func__, i->entry->fd, getpgrp(), i->mnt_path);

	init_autofs_dev_ioctl(&param);
	param.ioctlfd = mnt_fd;
	param.setpipefd.pipefd = i->entry->fd;

	return autofs_dev_ioctl(AUTOFS_DEV_IOCTL_SETPIPEFD, &param);
}

static int autofs_mnt_close(const char *mnt_path, int mnt_fd)
{
	struct autofs_dev_ioctl param;

	pr_info("%s: closing fd %d for mount %s\n", __func__, mnt_fd, mnt_path);

	init_autofs_dev_ioctl(&param);
	param.ioctlfd = mnt_fd;

	return autofs_dev_ioctl(AUTOFS_DEV_IOCTL_CLOSEMOUNT, &param);
}

static int autofs_mnt_open(const char *mnt_path, dev_t devid)
{
	struct autofs_dev_ioctl *param;
	int err;
	size_t size, fd;

	pr_info("%s: open mount %s\n", __func__, mnt_path);

	size = sizeof(*param) + strlen(mnt_path) + 1;
	param = xmalloc(size);
	if (!param)
		return -1;

	init_autofs_dev_ioctl(param);
	param->size = size;
	strcpy(param->path, mnt_path);
	param->openmount.devid = devid;

	err = autofs_dev_ioctl(AUTOFS_DEV_IOCTL_OPENMOUNT, param);
	fd = param->ioctlfd;
	free(param);
	if (err < 0) {
		pr_err("Failed to get %s fd (devid: %ld)\n", mnt_path, (long)devid);
		return -1;
	}
	return fd;
}

static int autofs_create_dentries(const struct mount_info *mi, char *mnt_path)
{
	struct mount_info *c;

	list_for_each_entry(c, &mi->children, siblings) {
		char *path, *basename;

		basename = strrchr(c->mountpoint, '/');
		if (!basename) {
			pr_info("%s: mount path \"%s\" doesn't have '/'\n", __func__, c->mountpoint);
			return -1;
		}
		path = xsprintf("%s%s", mnt_path, basename);
		if (!path)
			return -1;
		if (mkdir(path, 0555) < 0) {
			pr_perror("Failed to create autofs dentry %s", path);
			free(path);
			return -1;
		}
		free(path);
	}
	return 0;
}

static int autofs_populate_mount(const struct mount_info *mi, const AutofsEntry *entry)
{
	if (entry->mode != AUTOFS_MODE_INDIRECT)
		return 0;

	return autofs_create_dentries(mi, mi->mountpoint);
}

static int autofs_post_mount(const char *mnt_path, dev_t mnt_dev, time_t timeout)
{
	int mnt_fd;

	pr_info("%s: set timeout for %s and make it catatonic\n", __func__, mnt_path);

	mnt_fd = autofs_mnt_open(mnt_path, mnt_dev);
	if (mnt_fd < 0) {
		pr_err("Failed to open %s\n", mnt_path);
		return -1;
	}

	if (autofs_mnt_set_timeout(timeout, mnt_path, mnt_fd)) {
		pr_err("Failed to set timeout %ld for %s\n", timeout, mnt_path);
		return -1;
	}

	if (autofs_mnt_make_catatonic(mnt_path, mnt_fd)) {
		pr_err("Failed to set %s catatonic\n", mnt_path);
		return -1;
	}

	if (autofs_mnt_close(mnt_path, mnt_fd) < 0) {
		pr_err("Failed to close %s\n", mnt_path);
		return -1;
	}

	return 0;
}

/* Here to fixup Autofs mount */
static int autofs_post_open(struct file_desc *d, int fd)
{
	struct pipe_info *pi = container_of(d, struct pipe_info, d);
	autofs_info_t *i = container_of(pi, autofs_info_t, pi);
	int mnt_fd;

	pr_info("%s: restoring %s\n", __func__, i->mnt_path);

	mnt_fd = autofs_mnt_open(i->mnt_path, i->mnt_dev);
	if (mnt_fd < 0) {
		pr_err("Failed to open %s\n", i->mnt_path);
		return -1;
	}

	if (autofs_mnt_set_pipefd(i, mnt_fd)) {
		pr_err("Failed to set %s owner\n", i->mnt_path);
		return -1;
	}

	if (autofs_mnt_close(i->mnt_path, mnt_fd) < 0) {
		pr_err("Failed to close %s\n", i->mnt_path);
		return -1;
	}

	pr_info("autofs mount %s owner restored: pgrp=%d, fd=%d\n", i->mnt_path, getpgrp(), i->entry->fd);

	if (i->entry->has_read_fd) {
		pr_info("%s: pid %d, closing write end %d\n", __func__, getpid(), i->entry->fd);
		close(i->entry->fd);
	}

	pr_info("%s: pid %d, closing artificial pipe end %d\n", __func__, getpid(), fd);
	close(fd);
	return 0;
}

static autofs_info_t *autofs_create_info(const struct mount_info *mi, const struct file_desc *desc,
					 const autofs_info_t *info)
{
	autofs_info_t *i;

	i = shmalloc(sizeof(*i));
	if (!i)
		return NULL;

	i->mnt_path = shmalloc(strlen(mi->ns_mountpoint) + 1);
	if (!i->mnt_path)
		return NULL;

	/* Here we copy autofs dev_id and entry from private data to shared.
	 * See autofs_mount().
	 */
	i->entry = shmalloc(sizeof(*info->entry));
	if (!i->entry)
		return NULL;
	memcpy(i->entry, info->entry, sizeof(*info->entry));
	i->mnt_dev = info->mnt_dev;

	/* We need mountpoint to be able to open mount in autofs_post_open()
	 * callback. And this have to be internal path, because process cwd
	 * will be changed already. That's why ns_mountpoint is used. */
	strcpy(i->mnt_path, mi->ns_mountpoint);

	return i;
}

static struct fdinfo_list_entry *autofs_pipe_le(struct pstree_item *master, AutofsEntry *entry)
{
	struct fdinfo_list_entry *ple;
	int pipe_fd = entry->fd;

	if (entry->has_read_fd)
		pipe_fd = entry->read_fd;

	ple = find_used_fd(master, pipe_fd);
	if (!ple) {
		pr_err("Failed to find pipe fd %d in process %d\n", pipe_fd, vpid(master));
		return NULL;
	}
	if (ple->fe->type != FD_TYPES__PIPE) {
		pr_err("Fd %d in process %d is not a pipe: %d\n", pipe_fd, vpid(master), ple->fe->type);
		return NULL;
	}
	return ple;
}

static int autofs_open_pipefd(struct file_desc *d, int *new_fd)
{
	struct fdinfo_list_entry *fle = file_master(d);
	int ret;

	if (fle->stage < FLE_OPEN) {
		ret = open_pipe(d, new_fd);
		if (ret != 0)
			return ret;
		set_fds_event(fle->pid);
		return 1;
	}

	return autofs_post_open(d, fle->fe->fd);
}

static int autofs_create_pipe(struct pstree_item *task, autofs_info_t *i, struct fdinfo_list_entry *ple)
{
	struct pipe_info *pi = container_of(ple->desc, struct pipe_info, d);
	int fd = -1;
	FdinfoEntry *fe;
	unsigned flags = O_RDONLY;
	struct file_desc_ops *ops;
	PipeEntry *pe;

	fd = find_unused_fd(task, fd);

	ops = shmalloc(sizeof(*ops));
	if (!ops)
		return -1;
	memcpy(ops, pi->d.ops, sizeof(*ops));
	ops->open = autofs_open_pipefd;
	ops->type = FD_TYPES__AUTOFS_PIPE;

	pe = shmalloc(sizeof(*pe));
	if (!pe)
		return -1;

	pe->id = pi->pe->id;
	pe->pipe_id = pi->pe->pipe_id;
	pe->fown = pi->pe->fown;
	pe->flags = flags;

	if (collect_one_pipe_ops(&i->pi, &pe->base, ops) < 0) {
		pr_err("Failed to add pipe info for write end\n");
		return -1;
	}

	fe = dup_fdinfo(ple->fe, fd, flags);
	if (!fe)
		return -1;
	fe->type = FD_TYPES__AUTOFS_PIPE;

	pr_info("autofs: adding pipe fd %d, flags %#x to %d (with post_open)\n", fe->fd, fe->flags, vpid(task));
	return collect_fd(vpid(task), fe, rsti(task), false);
}

static int autofs_add_mount_info(struct pprep_head *ph)
{
	autofs_info_t *ai = container_of(ph, autofs_info_t, ph);
	struct mount_info *mi = ai->mi;
	autofs_info_t *info = mi->private;
	AutofsEntry *entry = info->entry;
	autofs_info_t *i;
	struct pstree_item *master;
	struct fdinfo_list_entry *ple;

	if (entry->fd == -1)
		/* Catatonic mounts have no owner. Keep them with init. */
		master = pstree_item_by_virt(getpid());
	else
		master = pstree_item_by_virt(entry->pgrp);
	BUG_ON(!master);

	ple = autofs_pipe_le(master, entry);
	if (!ple)
		return -1;

	if (entry->has_read_fd) {
		/* Original pipe write end was closed.
		 * We need create one to be able to fixup AutoFS mount. */

		entry->fd = autofs_dup_pipe(master, ple, entry->fd);
		if (entry->fd < 0) {
			pr_err("Failed to find free fd in process %d\n", vpid(master));
			return -1;
		}
	}

	i = autofs_create_info(mi, ple->desc, info);
	if (!i)
		return -1;

	/* Another pipe descriptor is needed to call post_open callback */
	if (autofs_create_pipe(master, i, ple))
		return -1;

	mi->private = i;

	return 0;
}

static int autofs_restore_entry(struct mount_info *mi, AutofsEntry **entry)
{
	struct cr_img *img;
	int ret;

	img = open_image(CR_FD_AUTOFS, O_RSTR, mi->s_dev);
	if (!img)
		return -1;
	if (empty_image(img)) {
		close_image(img);
		return -1;
	}

	ret = pb_read_one_eof(img, entry, PB_AUTOFS);

	close_image(img);
	if (ret < 0)
		return -1;
	return 0;
}

int autofs_mount(struct mount_info *mi, const char *source, const char *filesystemtype, unsigned long mountflags)
{
	AutofsEntry *entry;
	autofs_info_t *info;
	char *opts, *mode;
	int control_pipe[2], ret = -1;
	struct stat buf;

	if (autofs_restore_entry(mi, &entry) < 0)
		return -1;

	if (pipe(control_pipe) < 0) {
		pr_perror("Can't create pipe");
		return -1;
	}

	mode = "direct";
	if (entry->mode == AUTOFS_MODE_INDIRECT)
		mode = "indirect";
	if (entry->mode == AUTOFS_MODE_OFFSET)
		mode = "offset";

	opts = xsprintf("fd=%d,pgrp=%d,minproto=%d,maxproto=%d,%s", control_pipe[1], getpgrp(), entry->minproto,
			entry->maxproto, mode);
	if (opts && entry->has_uid)
		opts = xstrcat(opts, ",uid=%d", entry->uid);
	if (opts && entry->has_gid)
		opts = xstrcat(opts, ",gid=%d", entry->gid);
	if (!opts) {
		pr_err("Failed to create options string\n");
		goto close_pipe;
	}

	pr_info("autofs: mounting to %s with options: \"%s\"\n", mi->mountpoint, opts);

	if (mount(source, mi->mountpoint, filesystemtype, mountflags, opts) < 0) {
		pr_perror("Failed to mount autofs to %s", mi->mountpoint);
		goto free_opts;
	}

	info = xmalloc(sizeof(*info));
	if (!info)
		goto umount;
	info->entry = entry;

	/* We need autofs dev_id to be able to open direct mount point.
	 * But we can't call stat in autofs_add_mount_info(), because autofs
	 * mount can be overmounted. Thus we have to call it here. But shared
	 * data is not ready yet. So, let's put in on mi->private and copy to
	 * shared data in autofs_add_mount_info().
	 */
	if (stat(mi->mountpoint, &buf) < 0) {
		pr_perror("Failed to stat %s", mi->mountpoint);
		goto free_info;
	}
	info->mnt_dev = buf.st_dev;

	/* We need to create dentries for nested mounts */
	ret = autofs_populate_mount(mi, entry);
	if (ret < 0)
		goto free_info;

	/* In case of catatonic mounts all we need as the function call below */
	ret = autofs_post_mount(mi->mountpoint, buf.st_dev, entry->timeout);
	if (ret < 0)
		goto free_info;

	/* Otherwise we have to add shared object creation callback */
	if (entry->fd != AUTOFS_CATATONIC_FD) {
		info->ph.actor = autofs_add_mount_info;
		add_post_prepare_cb(&info->ph);
	}

	info->mi = mi;
	mi->private = info;

free_opts:
	free(opts);
close_pipe:
	close(control_pipe[1]);
	close(control_pipe[0]);
	return ret;

free_info:
	free(info);
umount:
	if (umount(mi->mountpoint) < 0)
		pr_perror("Failed to umount %s", mi->mountpoint);
	goto close_pipe;
}
