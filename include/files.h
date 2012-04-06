#ifndef FILES_H_
#define FILES_H_

#include "compiler.h"
#include "types.h"
#include "lock.h"
#include "list.h"
#include "image.h"

struct fd_parms {
	unsigned long	fd_name;
	unsigned long	pos;
	unsigned int	flags;
	unsigned int	type;
	struct stat	stat;
	u32		id;
	pid_t		pid;
};

enum fdinfo_states {
	FD_STATE_PREP,		/* Create unix sockets */
	FD_STATE_CREATE,	/* Create and send fd */
	FD_STATE_RECV,		/* Receive fd */

	FD_STATE_MAX
};

struct fmap_fd {
	struct fmap_fd		*next;
	unsigned long		start;
	int			pid;
	int			fd;
};

struct fdinfo_list_entry {
	struct list_head	list;
	int			fd;
	int			pid;
	futex_t			real_pid;
};

struct file_desc {
	struct list_head fd_info_head;
};

extern void file_desc_add(struct file_desc *d);
extern struct fdinfo_list_entry *file_master(struct file_desc *d);

extern void transport_name_gen(struct sockaddr_un *addr,
				int *len, int pid, long fd);

void show_saved_files(void);
extern int collect_reg_files(void);
extern int prepare_fds(int pid);
extern int prepare_fd_pid(int pid);
extern int prepare_shared_fdinfo(void);
extern int get_filemap_fd(int pid, struct vma_entry *vma_entry);

extern int self_exe_fd;

struct file_desc;
extern int collect_pipes(void);
extern void mark_pipe_master(void);
extern int open_pipe(struct file_desc *);
struct file_desc *find_pipe_desc(int id);
extern int pipe_should_open_transport(struct fdinfo_entry *fe,
		struct file_desc *d);

#endif /* FILES_H_ */
