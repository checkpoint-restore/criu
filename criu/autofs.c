#include "proc_parse.h"
#include "autofs.h"
#include "util.h"
#include "mount.h"

#define AUTOFS_OPT_UNKNOWN	INT_MIN

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
