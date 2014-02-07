#ifndef __CR_FILES_H__
#define __CR_FILES_H__

#include "compiler.h"
#include "asm/types.h"
#include "fcntl.h"
#include "lock.h"
#include "list.h"
#include "image.h"
#include "pid.h"
#include "rst_info.h"

#include "protobuf/fdinfo.pb-c.h"
#include "protobuf/fown.pb-c.h"
#include "protobuf/vma.pb-c.h"

struct pstree_item;
struct file_desc;
struct cr_fdset;
struct rst_info;
struct parasite_ctl;

struct fd_link {
	union {
		/* Link info for generic file (path) */
		struct {
			char	name[PATH_MAX + 1];
			size_t	len;
		};

		/* Link info for proc-ns file */
		struct {
			struct ns_desc *ns_d;
			unsigned int ns_kid;
		};
	};
};

struct fd_parms {
	int		fd;
	off_t		pos;
	unsigned int	flags;
	char		fd_flags;
	struct stat	stat;
	pid_t		pid;
	FownEntry	fown;
	struct fd_link	*link;
	long		fs_type;

	struct parasite_ctl *ctl;
};

#define FD_PARMS_INIT			\
(struct fd_parms) {			\
	.fd	= FD_DESC_INVALID,	\
	.fown	= FOWN_ENTRY__INIT,	\
	.link	= NULL,			\
}

extern int fill_fdlink(int lfd, const struct fd_parms *p, struct fd_link *link);

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
	return pid_rst_prio(fd_a->pid, fd_b->pid) ||
		((fd_a->pid == fd_b->pid) && (fd_a->fe->fd < fd_b->fe->fd));
}

struct file_desc_ops {
	/* fd_types from protobuf/fdinfo.proto */
	unsigned int		type;
	/*
	 * Opens a file by whatever syscall is required for that.
	 * The returned descriptor may be closed (dup2-ed to another)
	 * so it shouldn't be saved for any post-actions.
	 */
	int			(*open)(struct file_desc *d);
	/*
	 * Called on a file when all files of that type are opened
	 * and with the fd being the "restored" one.
	 */
	int			(*post_open)(struct file_desc *d, int fd);
	/*
	 * Report whether the fd in question wants a transport socket
	 * in it instead of a real file. See file_master for details.
	 */
	int			(*want_transport)(FdinfoEntry *fe, struct file_desc *d);
	/*
	 * Called to collect a new fd before adding it on desc. Clients
	 * may chose to collect it to some specific rst_info list. See
	 * prepare_fds() for details.
	 */
	void			(*collect_fd)(struct file_desc *, struct fdinfo_list_entry *,
						struct rst_info *);
};

static inline void collect_gen_fd(struct fdinfo_list_entry *fle, struct rst_info *ri)
{
	list_add_tail(&fle->ps_list, &ri->fds);
}

struct file_desc {
	u32			id;		/* File id, unique */
	struct hlist_node	hash;		/* Descriptor hashing and lookup */
	struct list_head	fd_info_head;	/* Chain of fdinfo_list_entry-s with same ID and type but different pids */
	struct file_desc_ops	*ops;		/* Associated operations */
};

struct fdtype_ops {
	unsigned int		type;
	int			(*dump)(int lfd, u32 id, const struct fd_parms *p);
	int			(*pre_dump)(int pid, int lfd);
};

extern int do_dump_gen_file(struct fd_parms *p, int lfd,
			    const struct fdtype_ops *ops,
			    const int fdinfo);
struct parasite_drain_fd;
int dump_task_files_seized(struct parasite_ctl *ctl, struct pstree_item *item,
		struct parasite_drain_fd *dfds);
int predump_task_files(int pid);

extern int file_desc_add(struct file_desc *d, u32 id, struct file_desc_ops *ops);
extern struct fdinfo_list_entry *file_master(struct file_desc *d);
extern struct file_desc *find_file_desc_raw(int type, u32 id);

extern int send_fd_to_peer(int fd, struct fdinfo_list_entry *fle, int sock);
extern int restore_fown(int fd, FownEntry *fown);
extern int rst_file_params(int fd, FownEntry *fown, int flags);

extern void show_saved_files(void);

extern int prepare_fds(struct pstree_item *me);
extern int prepare_fd_pid(struct pstree_item *me);
extern int prepare_ctl_tty(int pid, struct rst_info *rst_info, u32 ctl_tty_id);
extern int prepare_shared_fdinfo(void);
extern int get_filemap_fd(struct vma_area *);
extern int prepare_fs(int pid);
extern int set_fd_flags(int fd, int flags);

extern int close_old_fds(struct pstree_item *me);
#ifndef AT_EMPTY_PATH
#define AT_EMPTY_PATH 0x1000
#endif

#define LREMAP_PARAM	"link-remap"

extern int shared_fdt_prepare(struct pstree_item *item);

extern struct collect_image_info ext_file_cinfo;
extern int dump_unsupp_fd(struct fd_parms *p, int lfd,
			  const int fdinfo, char *more, char *info);

#endif /* __CR_FILES_H__ */
