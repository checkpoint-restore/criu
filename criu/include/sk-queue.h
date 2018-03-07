#ifndef __CR_SK_QUEUE_H__
#define __CR_SK_QUEUE_H__

extern struct collect_image_info sk_queues_cinfo;

#define SK_QUEUE_REAL_PID      0x1 /* scm creds contains a real pid */
extern int dump_sk_queue(int sock_fd, int sock_id, int flags);
extern int sk_queue_post_actions(void);
extern int restore_sk_queue(int fd, unsigned int peer_id);

#endif /* __CR_SK_QUEUE_H__ */
