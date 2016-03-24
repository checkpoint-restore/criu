#ifndef __CR_SK_QUEUE_H__
#define __CR_SK_QUEUE_H__

extern struct collect_image_info sk_queues_cinfo;
extern int dump_sk_queue(int sock_fd, int sock_id);
extern int restore_sk_queue(int fd, unsigned int peer_id);

#endif /* __CR_SK_QUEUE_H__ */
