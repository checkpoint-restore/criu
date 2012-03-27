#ifndef CR_SOCKETS_H__
#define CR_SOCKETS_H__

#include <sys/types.h>
#include <unistd.h>
#include <stdbool.h>

struct sk_queue_item {
	int		fd;
	int		type;
	unsigned int	sk_id;
};

struct sk_queue_entry {
	struct sk_queue_item item;
	struct sk_queue_entry *next;
};

struct sk_queue {
	unsigned int entries;
	struct sk_queue_entry *list;
};

struct cr_fdset;
extern int try_dump_socket(pid_t pid, int fd, const struct cr_fdset *cr_fdset,
			   struct sk_queue *queue);

extern int collect_sockets(void);
extern int prepare_sockets(int pid);
struct cr_options;
extern void show_unixsk(int fd, struct cr_options *);
extern void show_inetsk(int fd, struct cr_options *);
extern void show_sk_queues(int fd, struct cr_options *);

#endif /* CR_SOCKETS_H__ */
