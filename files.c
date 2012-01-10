#include <unistd.h>
#include <fcntl.h>

#include <linux/limits.h>

#include "crtools.h"

#include "files.h"
#include "image.h"
#include "list.h"
#include "util.h"
#include "lock.h"

struct fmap_fd {
	struct fmap_fd	*next;
	unsigned long	start;
	int		pid;
	int		fd;
};

static struct fmap_fd *fmap_fds;

static int get_file_path(char *path, struct fdinfo_entry *fe, int fd)
{
	if (read(fd, path, fe->len) != fe->len) {
		pr_err("Error reading path");
		return -1;
	}

	path[fe->len] = '\0';

	return 0;
}

static int open_fe_fd(struct fdinfo_entry *fe, int fd)
{
	char path[PATH_MAX];
	int tmp;

	if (get_file_path(path, fe, fd))
		return -1;

	tmp = open(path, fe->flags);
	if (tmp < 0) {
		pr_perror("Can't open file %s\n", path);
		return -1;
	}

	lseek(tmp, fe->pos, SEEK_SET);

	return tmp;
}

static int restore_cwd(struct fdinfo_entry *fe, int fd)
{
	char path[PATH_MAX];
	int ret;

	if (get_file_path(path, fe, fd))
		return -1;

	pr_info("Restore CWD %s\n", path);
	ret = chdir(path);
	if (ret < 0) {
		pr_perror("Can't change dir %s\n", path);
		return -1;
	}

	return 0;
}

static int open_fd(int pid, struct fdinfo_entry *fe, int *cfd)
{
	int fd, tmp;

	if (move_img_fd(cfd, (int)fe->addr))
		return -1;

	if (fe->addr == ~0L)
		return restore_cwd(fe, *cfd);

	tmp = open_fe_fd(fe, *cfd);
	if (tmp < 0)
		return -1;

	return reopen_fd_as((int)fe->addr, tmp);
}

static int open_fmap(int pid, struct fdinfo_entry *fe, int fd)
{
	int tmp;
	struct fmap_fd *new;

	tmp = open_fe_fd(fe, fd);
	if (tmp < 0)
		return -1;

	pr_info("%d:\t\tWill map %lx to %d\n", pid, (unsigned long)fe->addr, tmp);

	new		= malloc(sizeof(*new));
	new->start	= fe->addr;
	new->fd		= tmp;
	new->next	= fmap_fds;
	new->pid	= pid;

	fmap_fds	= new;

	return 0;
}

int prepare_fds(int pid)
{
	int fdinfo_fd;

	pr_info("%d: Opening files img\n", pid);

	fdinfo_fd = open_image_ro(CR_FD_FDINFO, pid);
	if (fdinfo_fd < 0)
		return -1;

	while (1) {
		int ret;
		struct fdinfo_entry fe;

		ret = read(fdinfo_fd, &fe, sizeof(fe));
		if (ret == 0) {
			close(fdinfo_fd);
			return 0;
		}

		if (ret < 0) {
			pr_perror("Error reading %d fdinfo\n", pid);
			return -1;
		}

		if (ret != sizeof(fe)) {
			pr_err("Corrupted %d fdinfo\n", pid);
			return -1;
		}

		pr_info("\t%d: Got fd for %lx type %d namelen %d\n", pid,
			(unsigned long)fe.addr, fe.type, fe.len);
		switch (fe.type) {
		case FDINFO_FD:
			if (open_fd(pid, &fe, &fdinfo_fd))
				return -1;
			break;
		case FDINFO_MAP:
			if (open_fmap(pid, &fe, fdinfo_fd))
				return -1;
			break;
		default:
			pr_err("Unknown %d fdinfo file type\n", pid);
			return -1;
		}
	}
}

static struct fmap_fd *pop_fmap_fd(int pid, unsigned long start)
{
	struct fmap_fd **p, *r;

	pr_info("%d: Looking for %lx : ", pid, start);

	for (p = &fmap_fds; *p != NULL; p = &(*p)->next) {
		if ((*p)->start != start || (*p)->pid != pid)
			continue;

		r = *p;
		*p = r->next;
		pr_info("found\n");

		return r;
	}

	pr_info("not found\n");
	return NULL;
}

int try_fixup_file_map(int pid, struct vma_entry *vma_entry, int fd)
{
	struct fmap_fd *fmap_fd = pop_fmap_fd(pid, vma_entry->start);

	if (fmap_fd) {
		pr_info("%d: Fixing %lx vma to %d fd\n",
			pid, vma_entry->start, fmap_fd->fd);

		lseek(fd, -sizeof(*vma_entry), SEEK_CUR);
		vma_entry->fd = fmap_fd->fd;

		write_ptr_safe(fd, vma_entry, err);

		free(fmap_fd);
	}

	return 0;
err:
	pr_perror("%d: Can't fixup vma\n", pid);
	return -1;
}
