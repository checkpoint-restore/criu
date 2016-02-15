#ifndef __CR_SHOW_H__
#define __CR_SHOW_H__

#include <stdbool.h>
#include "asm/types.h"

struct cr_img;

struct show_image_info {
	u32	magic;
	int	pb_type;
	bool	single;
	void	(*payload)(struct cr_img *, void *);
	char	*fmt;
};

extern void show_siginfo(struct cr_img *);
extern void sk_queue_data_handler(struct cr_img *, void *obj);
extern void ipc_shm_handler(struct cr_img *, void *obj);
extern void ipc_msg_handler(struct cr_img *, void *obj);
extern void ipc_sem_handler(struct cr_img *, void *obj);
extern int cr_parse_fd(struct cr_img *, u32 magic);
extern void show_tcp_stream(struct cr_img *, void *obj);

#endif /* __CR_SHOW_H__ */
