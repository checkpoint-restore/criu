#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <limits.h>
#include <unistd.h>
#include <errno.h>
#include <dirent.h>

#include <fcntl.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/vfs.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <sys/sendfile.h>

#include "types.h"
#include "list.h"

#include "compiler.h"
#include "crtools.h"
#include "util.h"

struct page_entry zero_page_entry;

static struct cr_fd_desc_tmpl template[CR_FD_MAX] = {
	[CR_FD_FDINFO] = {
		.fmt	= "fdinfo-%li.img",
		.magic	= FDINFO_MAGIC,
	},
	[CR_FD_PAGES] = {
		.fmt	= "pages-%li.img",
		.magic	= PAGES_MAGIC,
	},
	[CR_FD_PAGES_SHMEM] = {
		.fmt	= "pages-shmem-%li.img",
		.magic	= PAGES_MAGIC,
	},
	[CR_FD_CORE] = {
		.fmt	= "core-%li.img",
		.magic	= CORE_MAGIC,
	},
	[CR_FD_PIPES] = {
		.fmt	= "pipes-%li.img",
		.magic	= PIPES_MAGIC,
	},
	[CR_FD_PSTREE] = {
		.fmt	= "pstree-%li.img",
		.magic	= PSTREE_MAGIC,
	},
	[CR_FD_SHMEM] = {
		.fmt	= "shmem-%li.img",
		.magic	= SHMEM_MAGIC,
	},
};

struct cr_fdset *alloc_cr_fdset(pid_t pid)
{
	struct cr_fdset *cr_fdset;
	unsigned int i;

	cr_fdset = xzalloc(sizeof(*cr_fdset));
	if (!cr_fdset)
		goto err;

	for (i = 0; i < CR_FD_MAX; i++) {
		cr_fdset->desc[i].tmpl = &template[i];
		snprintf(cr_fdset->desc[i].name,
			 sizeof(cr_fdset->desc[i].name),
			 cr_fdset->desc[i].tmpl->fmt,
			 (long)pid);
		cr_fdset->desc[i].fd = -1;
	}

err:
	return cr_fdset;
}

int prep_cr_fdset_for_dump(struct cr_fdset *cr_fdset,
			    unsigned long use_mask)
{
	unsigned int i;
	u32 magic;
	int ret = -1;

	if (!cr_fdset)
		goto err;

	cr_fdset->use_mask = use_mask;

	for (i = 0; i < CR_FD_MAX; i++) {
		if (!(use_mask & CR_FD_DESC_USE(i)))
			continue;

		ret = unlink(cr_fdset->desc[i].name);
		if (ret && errno != ENOENT) {
			pr_perror("Unable to unlink %s (%s)\n",
				 cr_fdset->desc[i].name,
				 strerror(errno));
			goto err;
		} else
			ret = -1;
		cr_fdset->desc[i].fd = open(cr_fdset->desc[i].name,
					    O_RDWR | O_CREAT | O_EXCL,
					    CR_FD_PERM);
		if (cr_fdset->desc[i].fd < 0) {
			pr_perror("Unable to open %s (%s)\n",
				 cr_fdset->desc[i].name,
				 strerror(errno));
			goto err;
		}

		pr_debug("Opened %s with %d\n",
			 cr_fdset->desc[i].name,
			 cr_fdset->desc[i].fd);

		magic = cr_fdset->desc[i].tmpl->magic;
		write_ptr_safe(cr_fdset->desc[i].fd, &magic, err);

		/*
		 * Make sure it's on disk since we might
		 * need to re-open files in parasite.
		 */
		fsync(cr_fdset->desc[i].fd);
	}
	ret = 0;
err:
	return ret;
}

int prep_cr_fdset_for_restore(struct cr_fdset *cr_fdset,
			       unsigned long use_mask)
{
	unsigned int i;
	int ret = -1;
	u32 magic;

	if (!cr_fdset)
		goto err;

	cr_fdset->use_mask = use_mask;

	for (i = 0; i < CR_FD_MAX; i++) {
		if (!(use_mask & CR_FD_DESC_USE(i)))
			continue;

		cr_fdset->desc[i].fd = open(cr_fdset->desc[i].name,
					    O_RDWR, CR_FD_PERM);
		if (cr_fdset->desc[i].fd < 0) {
			pr_perror("Unable to open %s (%s)\n",
				 cr_fdset->desc[i].name,
				 strerror(errno));
			goto err;
		}

		pr_debug("Opened %s with %d\n",
			 cr_fdset->desc[i].name,
			 cr_fdset->desc[i].fd);

		read_ptr_safe(cr_fdset->desc[i].fd, &magic, err);
		if (magic != cr_fdset->desc[i].tmpl->magic) {
			pr_error("Magic doesn't match for %s\n",
				 cr_fdset->desc[i].name);
			goto err;
		}

	}
	ret = 0;
err:
	return ret;
}

void close_cr_fdset(struct cr_fdset *cr_fdset)
{
	unsigned int i;

	if (!cr_fdset)
		return;

	for (i = 0; i < CR_FD_MAX; i++) {
		if (!(cr_fdset->use_mask & CR_FD_DESC_USE(i)))
			continue;

		if (cr_fdset->desc[i].fd >= 0) {
			pr_debug("Closed %s with %d\n",
				cr_fdset->desc[i].name,
				cr_fdset->desc[i].fd);
			close(cr_fdset->desc[i].fd);
			cr_fdset->desc[i].fd = -1;
		}
	}
}

void free_cr_fdset(struct cr_fdset **cr_fdset)
{
	if (cr_fdset && *cr_fdset) {
		free(*cr_fdset);
		*cr_fdset = NULL;
	}
}

int main(int argc, char *argv[])
{
	pid_t pid;
	int ret = -1;

	BUILD_BUG_ON(PAGE_SIZE != PAGE_IMAGE_SIZE);

	if (argc < 3)
		goto usage;

	memset(&zero_page_entry, 0, sizeof(zero_page_entry));

	if (!strcmp(argv[1], "dump")) {
		bool leader_only;

		switch (argv[2][1]) {
		case 'p':
			pid = atol(argv[3]);
			leader_only = true;
			break;
		case 't':
			pid = atol(argv[3]);
			leader_only = false;
			break;
		default:
			goto usage;
		}

		ret = cr_dump_tasks(pid, leader_only, 1);

	} else if (!strcmp(argv[1], "restore")) {
		bool leader_only;

		switch (argv[2][1]) {
		case 'p':
			pid = atol(argv[3]);
			leader_only = true;
			break;
		case 't':
			pid = atol(argv[3]);
			leader_only = false;
			break;
		default:
			goto usage;
		}

		ret = cr_restore_tasks(pid, leader_only, 1);

	} else if (!strcmp(argv[1], "show")) {
		bool leader_only = true;

		switch (argv[2][1]) {
		case 'p':
			leader_only = true;
			pid = atol(argv[3]);
			break;
		case 't':
			leader_only = false;
			pid = atol(argv[3]);
			break;
		default:
			goto usage;
		}

		ret = cr_show(pid, leader_only);

	} else
		goto usage;

	return ret;

usage:
	printk("\nUsage:\n");
	printk("\tcrtools (dump|show|restore) (-p|-t) pid\n\n");
	return -1;
}
