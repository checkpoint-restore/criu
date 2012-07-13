#ifndef SK_QUEUE_H__
#define SK_QUEUE_H__

#include "types.h"
#include "list.h"
#include "crtools.h"
#include "image.h"

struct sk_packet {
	struct list_head	list;
	struct sk_packet_entry	*entry;
	off_t			img_off;
};

extern int read_sk_queues(void);
extern int dump_sk_queue(int sock_fd, int sock_id);
extern void show_sk_queues(int fd, struct cr_options *o);
extern int restore_sk_queue(int fd, unsigned int peer_id);

#endif /* SK_QUEUE_H__ */
