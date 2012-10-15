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
struct parasite_ctl;

struct fd_parms {
	int		fd;
	unsigned long	pos;
	unsigned int	flags;
	char		fd_flags;
	struct stat	stat;
	pid_t		pid;
	FownEntry	fown;

	struct parasite_ctl *ctl;
};

#define FD_PARMS_INIT			\
{					\
	.fd	= FD_DESC_INVALID,	\
	.fown	= FOWN_ENTRY__INIT,	\
}

struct file_desc;

struct fdinfo_list_entry {
	struct list_head	desc_list;	/* To chain on  @fd_info_head */
	struct file_desc	*desc;		/* Associated file descriptor */
	struct list_head	ps_list;	/* To chain  per-task files */
	int			pid;
	futex_t			real_pid;
	FdinfoEntry		*fe;
};

/* reports whether fd_a takes prio over fd_b */
static inline int fdinfo_rst_prio(struct fdinfo_list_entry *fd_a, struct fdinfo_list_entry *fd_b)
{
	return (fd_a->pid < fd_b->pid) || ((fd_a->pid == fd_b->pid) && (fd_a->fe->fd < fd_b->fe->fd));
}

struct file_desc_ops {
	unsigned int		type;
	int			(*open)(struct file_desc *d);
	int			(*post_open)(struct file_desc *d, int fd);
	int			(*want_transport)(FdinfoEntry *fe, struct file_desc *d);
	struct list_head *	(*select_ps_list)(struct file_desc *, struct rst_info *);
};

struct file_desc {
	u32			id;		/* File descriptor id, unique */
	struct list_head	hash;		/* Descriptor hashing and lookup */
	struct list_head	fd_info_head;	/* Chain of fdinfo_list_entry-s with same ID and type but different pids */
	struct file_desc_ops	*ops;		/* Associated operations */
};

struct fdtype_ops {
	unsigned int		type;
	int			(*dump)(int lfd, u32 id, const struct fd_parms *p);
};

extern int do_dump_gen_file(struct fd_parms *p, int lfd,
			    const struct fdtype_ops *ops,
			    const struct cr_fdset *cr_fdset);

extern void file_desc_add(struct file_desc *d, u32 id, struct file_desc_ops *ops);
extern struct fdinfo_list_entry *file_master(struct file_desc *d);
extern struct file_desc *find_file_desc_raw(int type, u32 id);

extern int send_fd_to_peer(int fd, struct fdinfo_list_entry *fle, int sock);
extern int restore_fown(int fd, FownEntry *fown);
extern int rst_file_params(int fd, FownEntry *fown, int flags);

extern void show_saved_files(void);

extern int prepare_fds(struct pstree_item *me);
extern int prepare_fd_pid(int pid, struct rst_info *rst_info);
extern int prepare_ctl_tty(int pid, struct rst_info *rst_info, u32 ctl_tty_id);
extern int prepare_shared_fdinfo(void);
extern int get_filemap_fd(int pid, VmaEntry *vma_entry);
extern int prepare_fs(int pid);
extern int set_fd_flags(int fd, int flags);

#ifndef AT_EMPTY_PATH
#define AT_EMPTY_PATH 0x1000
#endif

#define LREMAP_PARAM	"link-remap"

#endif /* FILES_H_ */
