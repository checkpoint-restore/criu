#ifndef __CR_MQUEUE_H__
#define __CR_MQUEUE_H__

#include <mqueue.h>
#include "files.h"
#include "images/mqueue.pb-c.h"

struct mqueue_file_info {
	PmqfdEntry		*mfe;
	struct file_desc	 d;
};

extern struct collect_image_info pmqfd_cinfo;

int dump_pmq_fd(int lfd, struct fd_parms *p, FdinfoEntry *e);
int intrusive_mq_peek_all(mqd_t fd, struct cr_img *img,
			   long curmsgs, long msgsize);
int restore_pmq_messages(struct cr_img *img, PmqDataEntry *pmd);

#endif /* __CR_MQUEUE_H__ */