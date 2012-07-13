#ifndef SK_QUEUE_H__
#define SK_QUEUE_H__

#include "types.h"
#include "list.h"
#include "crtools.h"
#include "image.h"

extern int read_sk_queues(void);
extern int dump_sk_queue(int sock_fd, int sock_id);
extern void show_sk_queues(int fd, struct cr_options *o);
extern int restore_sk_queue(int fd, unsigned int peer_id);

#endif /* SK_QUEUE_H__ */
