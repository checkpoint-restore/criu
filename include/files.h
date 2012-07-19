#ifndef FILES_H_
#define FILES_H_

#include "compiler.h"
#include "types.h"
#include "lock.h"
#include "list.h"
#include "image.h"

#include "../protobuf/fdinfo.pb-c.h"
#include "../protobuf/fown.pb-c.h"
#include "../protobuf/vma.pb-c.h"

struct pstree_item;
struct file_desc;
struct cr_fdset;
struct rst_info;

struct fd_parms {
	int		fd;
	unsigned long	pos;
	unsigned int	flags;
	char		fd_flags;
	struct stat	stat;
	pid_t		pid;
	FownEntry	fown;
};

#define FD_PARMS_INIT			\
{					\
	.fd	= FD_DESC_INVALID,	\
	.fown	= FOWN_ENTRY__INIT,	\
}

enum fdinfo_states {
	FD_STATE_PREP,		/* Create unix sockets */
	FD_STATE_CREATE,	/* Create and send fd */
	FD_STATE_RECV,		/* Receive fd */

	FD_STATE_MAX
};

struct file_desc;

struct fdinfo_list_entry {
	struct list_head	desc_list;
	struct file_desc	*desc;
	struct list_head	ps_list;
	int			pid;
	futex_t			real_pid;
	FdinfoEntry		*fe;
};

struct file_desc_ops {
	unsigned int		type;
	int			(*open)(struct file_desc *d);
	int			(*want_transport)(FdinfoEntry *fe, struct file_desc *d);
};

struct file_desc {
	u32			id;
	struct list_head	hash;
	struct list_head	fd_info_head;
	struct file_desc_ops	*ops;
};

struct fdtype_ops {
	unsigned int		type;
	u32			(*make_gen_id)(const struct fd_parms *p);
	int			(*dump)(int lfd, u32 id, const struct fd_parms *p);
};

extern u32 make_gen_id(const struct fd_parms *p);
extern int do_dump_gen_file(struct fd_parms *p, int lfd,
			    const struct fdtype_ops *ops,
			    const struct cr_fdset *cr_fdset);

extern void file_desc_add(struct file_desc *d, u32 id, struct file_desc_ops *ops);
extern struct fdinfo_list_entry *file_master(struct file_desc *d);
extern struct file_desc *find_file_desc_raw(int type, u32 id);

extern int send_fd_to_peer(int fd, struct fdinfo_list_entry *fle, int transport);
extern int restore_fown(int fd, FownEntry *fown);
extern int rst_file_params(int fd, FownEntry *fown, int flags);

extern void show_saved_files(void);

extern int prepare_fds(struct pstree_item *me);
extern int prepare_fd_pid(int pid, struct rst_info *rst_info);
extern int prepare_shared_fdinfo(void);
extern int get_filemap_fd(int pid, VmaEntry *vma_entry);
extern int prepare_fs(int pid);
extern int set_fd_flags(int fd, int flags);

extern int self_exe_fd;

#endif /* FILES_H_ */
