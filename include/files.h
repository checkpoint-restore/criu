#ifndef FILES_H_
#define FILES_H_

#include "compiler.h"
#include "types.h"
#include "lock.h"
#include "list.h"
#include "image.h"

struct fd_parms {
	int		fd;
	unsigned long	pos;
	unsigned int	flags;
	unsigned int	type;
	char		fd_flags;
	struct stat	stat;
	u32		id;
	pid_t		pid;
	fown_t		fown;
};

enum fdinfo_states {
	FD_STATE_PREP,		/* Create unix sockets */
	FD_STATE_CREATE,	/* Create and send fd */
	FD_STATE_RECV,		/* Receive fd */

	FD_STATE_MAX
};

struct fdinfo_list_entry {
	struct list_head	list;
	int			fd;
	int			pid;
	int			flags;
	futex_t			real_pid;
};

struct file_desc;

struct file_desc_ops {
	int (*open)(struct file_desc *);
	int (*want_transport)(struct fdinfo_entry *, struct file_desc *);
};

struct file_desc {
	int type;
	u32 id;
	struct list_head hash;
	struct list_head fd_info_head;
	struct file_desc_ops *ops;
};

extern void file_desc_add(struct file_desc *d, int type, u32 id,
		struct file_desc_ops *ops);
extern struct fdinfo_list_entry *file_master(struct file_desc *d);
extern struct file_desc *find_file_desc_raw(int type, u32 id);
extern int send_fd_to_peer(int fd, struct fdinfo_list_entry *, int transport);
extern int restore_fown(int fd, fown_t *fown);

void show_saved_files(void);
extern int collect_reg_files(void);
extern int prepare_fds(int pid);
extern int prepare_fd_pid(int pid);
extern int prepare_shared_fdinfo(void);
extern int get_filemap_fd(int pid, struct vma_entry *vma_entry);
extern int prepare_fs(int pid);
extern int open_reg_by_id(u32 id);
int set_fd_flags(int fd, int flags);

extern int self_exe_fd;

struct file_desc;
extern int collect_pipes(void);
extern void mark_pipe_master(void);

void clear_ghost_files(void);

#endif /* FILES_H_ */
