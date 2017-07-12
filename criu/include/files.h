#ifndef __CR_FILES_H__
#define __CR_FILES_H__

#include <sys/stat.h>

#include "int.h"
#include "common/compiler.h"
#include "fcntl.h"
#include "common/lock.h"
#include "common/list.h"
#include "pid.h"
#include "rst_info.h"

#include "images/fdinfo.pb-c.h"
#include "images/fown.pb-c.h"
#include "images/vma.pb-c.h"

struct pstree_item;
struct file_desc;
struct cr_imgset;
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
	int		mnt_id;

	struct parasite_ctl *fd_ctl;
};

#define FD_PARMS_INIT			\
(struct fd_parms) {			\
	.fd	= FD_DESC_INVALID,	\
	.fown	= FOWN_ENTRY__INIT,	\
	.link	= NULL,			\
	.mnt_id = -1,			\
}

extern int fill_fdlink(int lfd, const struct fd_parms *p, struct fd_link *link);

struct file_desc;

enum {
	FLE_INITIALIZED,
	/*
	 * FLE is open (via open() or socket() or etc syscalls), and
	 * common file setting are set up (type-specific are not yet).
	 * Most possible, the master was already served out.
	 */
	FLE_OPEN,
	/*
	 * File-type specific settings and preparations are finished,
	 * and FLE is completely restored.
	 */
	FLE_RESTORED,
};

struct fdinfo_list_entry {
	struct list_head	desc_list;	/* To chain on  @fd_info_head */
	struct file_desc	*desc;		/* Associated file descriptor */
	struct list_head	ps_list;	/* To chain  per-task files */
	int			pid;
	FdinfoEntry		*fe;
	u8			received:1;
	u8			stage:3;
};

static inline void fle_init(struct fdinfo_list_entry *fle, int pid, FdinfoEntry *fe)
{
	fle->pid = pid;
	fle->fe = fe;
	fle->received = 0;
	fle->stage = FLE_INITIALIZED;
}

/* reports whether fd_a takes prio over fd_b */
static inline int fdinfo_rst_prio(struct fdinfo_list_entry *fd_a, struct fdinfo_list_entry *fd_b)
{
	return pid_rst_prio(fd_a->pid, fd_b->pid) ||
		((fd_a->pid == fd_b->pid) && (fd_a->fe->fd < fd_b->fe->fd));
}

struct file_desc_ops {
	/* fd_types from images/fdinfo.proto */
	unsigned int		type;
	/*
	 * Opens a file by whatever syscall is required for that.
	 * The returned descriptor may be closed (dup2-ed to another)
	 * so it shouldn't be saved for any post-actions.
	 */
	int			(*open)(struct file_desc *d, int *new_fd);
	/*
	 * Called to collect a new fd before adding it on desc. Clients
	 * may chose to collect it to some specific rst_info list. See
	 * prepare_fds() for details.
	 */
	void			(*collect_fd)(struct file_desc *, struct fdinfo_list_entry *,
						struct rst_info *);
	char *			(*name)(struct file_desc *, char *b, size_t s);
};

void collect_task_fd(struct fdinfo_list_entry *new_fle, struct rst_info *ri);

unsigned int find_unused_fd(struct pstree_item *, int hint_fd);
struct fdinfo_list_entry *find_used_fd(struct pstree_item *, int fd);

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

struct cr_img;

extern int do_dump_gen_file(struct fd_parms *p, int lfd,
			    const struct fdtype_ops *ops,
			    struct cr_img *);
struct parasite_drain_fd;
int dump_task_files_seized(struct parasite_ctl *ctl, struct pstree_item *item,
		struct parasite_drain_fd *dfds);
int predump_task_files(int pid);

extern void file_desc_init(struct file_desc *d, u32 id, struct file_desc_ops *ops);
extern int file_desc_add(struct file_desc *d, u32 id, struct file_desc_ops *ops);
extern struct fdinfo_list_entry *file_master(struct file_desc *d);
extern struct file_desc *find_file_desc_raw(int type, u32 id);

extern int recv_desc_from_peer(struct file_desc *d, int *fd);
extern int send_desc_to_peer(int fd, struct file_desc *d);
extern int restore_fown(int fd, FownEntry *fown);
extern int rst_file_params(int fd, FownEntry *fown, int flags);

extern void show_saved_files(void);

extern int prepare_fds(struct pstree_item *me);
extern int prepare_fd_pid(struct pstree_item *me);
extern int prepare_ctl_tty(int pid, struct rst_info *rst_info, u32 ctl_tty_id);
extern int prepare_files(void);
extern int restore_fs(struct pstree_item *);
extern int prepare_fs_pid(struct pstree_item *);
extern int set_fd_flags(int fd, int flags);

extern struct collect_image_info files_cinfo;
#define files_collected() (files_cinfo.flags & COLLECT_HAPPENED)

extern int close_old_fds(void);
#ifndef AT_EMPTY_PATH
#define AT_EMPTY_PATH 0x1000
#endif

#define LREMAP_PARAM	"link-remap"

extern int shared_fdt_prepare(struct pstree_item *item);

extern struct collect_image_info ext_file_cinfo;
extern int dump_unsupp_fd(struct fd_parms *p, int lfd,
			  struct cr_img *, char *more, char *info);

extern int inherit_fd_parse(char *optarg);
extern int inherit_fd_add(int fd, char *key);
extern void inherit_fd_log(void);
extern int inherit_fd_resolve_clash(int fd);
extern int inherit_fd_fini(void);

extern int inherit_fd_lookup_id(char *id);

extern bool inherited_fd(struct file_desc *, int *fdp);

extern FdinfoEntry *dup_fdinfo(FdinfoEntry *old, int fd, unsigned flags);
int dup_fle(struct pstree_item *task, struct fdinfo_list_entry *ple,
	    int fd, unsigned flags);

extern int open_transport_socket(void);
extern int set_fds_event(pid_t virt);
extern void wait_fds_event(void);

#endif /* __CR_FILES_H__ */
