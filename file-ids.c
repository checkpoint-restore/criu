#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <signal.h>
#include <limits.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

#include <sys/types.h>

#include "types.h"
#include "file-ids.h"
#include "rbtree.h"
#include "kcmp-ids.h"
#include "compiler.h"
#include "syscall.h"
#include "image.h"
#include "util.h"

static DECLARE_KCMP_TREE(fd_tree, KCMP_FILE);

void fd_id_show_tree(void)
{
	kid_show_tree(&fd_tree);
}

u32 fd_id_generate_special(void)
{
	return fd_tree.subid++;
}

int fd_id_generate(pid_t pid, FdinfoEntry *fe)
{
	u32 id;
	struct kid_elem e;
	int new_id = 0;

	e.pid = pid;
	e.genid = fe->id;
	e.idx = fe->fd;

	id = kid_generate_gen(&fd_tree, &e, &new_id);
	if (!id)
		return -ENOMEM;

	fe->id = id;
	return new_id;
}
