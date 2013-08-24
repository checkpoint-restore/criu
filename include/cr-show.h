#ifndef __CR_SHOW_H__
#define __CR_SHOW_H__
#include <stdbool.h>

struct show_image_info {
	u32	magic;
	int	pb_type;
	bool	single;
	void	(*payload)(int, void *);
	char	*fmt;
};

extern void show_siginfo(int fd);
extern void sk_queue_data_handler(int fd, void *obj);
extern void ipc_shm_handler(int fd, void *obj);
extern void ipc_msg_handler(int fd, void *obj);
extern void ipc_sem_handler(int fd, void *obj);
extern int cr_parse_fd(int fd, u32 magic);
#endif /* __CR_SHOW_H__ */
