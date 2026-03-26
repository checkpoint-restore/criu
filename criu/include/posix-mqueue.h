#ifndef __CR_MQUEUE_H__
#define __CR_MQUEUE_H__

#include <mqueue.h>
#include <stdint.h>
#include "files.h"
#include "images/posix-mqueue.pb-c.h"

struct mqueue_message {
	uint32_t prio;
	uint32_t len;
	char *data;
};

extern struct collect_image_info pmqfd_cinfo;

struct mqueue_file_info {
	IpcnsPmqDataEntry *mfe;
	struct file_desc d;
	int fd;
	struct list_head rlist;
};

extern const struct fdtype_ops pmq_dump_ops;

extern int pmq_peek_messages(int fd, struct mqueue_message *msgs, long nmsgs, long msgsize);

#endif /* __CR_MQUEUE_H__ */
