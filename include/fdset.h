#ifndef __CR_FDSET_H__
#define __CR_FDSET_H__

#include "image-desc.h"
#include "bug.h"

struct cr_fdset {
	int fd_off;
	int fd_nr;
	int *_fds;
};

static inline int fdset_fd(const struct cr_fdset *fdset, int type)
{
	int idx;

	idx = type - fdset->fd_off;
	BUG_ON(idx > fdset->fd_nr);

	return fdset->_fds[idx];
}

extern struct cr_fdset *glob_fdset;

extern struct cr_fd_desc_tmpl fdset_template[CR_FD_MAX];

extern struct cr_fdset *cr_task_fdset_open(int pid, int mode);
extern struct cr_fdset *cr_fdset_open_range(int pid, int from, int to,
					    unsigned long flags);
#define cr_fdset_open(pid, type, flags) cr_fdset_open_range(pid, \
		_CR_FD_##type##_FROM, _CR_FD_##type##_TO, flags)
extern struct cr_fdset *cr_glob_fdset_open(int mode);

extern void close_cr_fdset(struct cr_fdset **cr_fdset);

#endif /* __CR_FDSET_H__ */
