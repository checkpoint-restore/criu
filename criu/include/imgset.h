#ifndef __CR_IMGSET_H__
#define __CR_IMGSET_H__

#include "image-desc.h"
#include "log.h"
#include "common/bug.h"
#include "image.h"

struct cr_imgset {
	int fd_off;
	int fd_nr;
	struct cr_img **_imgs;
};

static inline struct cr_img *img_from_set(const struct cr_imgset *imgset, int type)
{
	int idx;

	idx = type - imgset->fd_off;
	BUG_ON(idx > imgset->fd_nr);

	return imgset->_imgs[idx];
}

extern struct cr_imgset *glob_imgset;

extern struct cr_fd_desc_tmpl imgset_template[CR_FD_MAX];

extern struct cr_imgset *cr_task_imgset_open(int pid, int mode);
extern struct cr_imgset *cr_imgset_open_range(int pid, int from, int to, unsigned long flags);
#define cr_imgset_open(pid, type, flags) cr_imgset_open_range(pid, _CR_FD_##type##_FROM, _CR_FD_##type##_TO, flags)
extern struct cr_imgset *cr_glob_imgset_open(int mode);

extern void close_cr_imgset(struct cr_imgset **cr_imgset);

#endif /* __CR_IMGSET_H__ */
