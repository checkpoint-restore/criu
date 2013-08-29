#ifndef __CR_CRTOOLS_H__
#define __CR_CRTOOLS_H__

#include <sys/types.h>

#include "list.h"
#include "asm/types.h"
#include "list.h"
#include "util.h"
#include "image.h"
#include "lock.h"
#include "cr-show.h"

#include "protobuf/vma.pb-c.h"

#define CR_FD_PERM		(S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH)

struct script {
	struct list_head node;
	char *path;
};

struct cr_options {
	int			final_state;
	char			*show_dump_file;
	bool			check_ms_kernel;
	bool			show_pages_content;
	bool			restore_detach;
	bool			ext_unix_sk;
	bool			shell_job;
	bool			handle_file_locks;
	bool			tcp_established_ok;
	bool			evasive_devices;
	bool			link_remap_ok;
	unsigned int		rst_namespaces_flags;
	bool			log_file_per_pid;
	char			*output;
	char			*root;
	char			*pidfile;
	struct list_head	veth_pairs;
	struct list_head	scripts;
	bool			use_page_server;
	unsigned short		ps_port;
	char			*addr;
	bool			track_mem;
	char			*img_parent;
};

extern struct cr_options opts;

enum sfd_type {
	SERVICE_FD_MIN,

	LOG_FD_OFF,
	LOG_DIR_FD_OFF,
	IMG_FD_OFF,
	SELF_EXE_FD_OFF,
	PROC_FD_OFF,
	CTL_TTY_OFF,
	SELF_STDIN_OFF,
	PARENT_FD_OFF,

	SERVICE_FD_MAX
};

#define CR_PARENT_LINK	"parent"

extern int clone_service_fd(int id);
extern int init_service_fd(void);
extern int get_service_fd(enum sfd_type type);
extern int reserve_service_fd(enum sfd_type type);
extern int install_service_fd(enum sfd_type type, int fd);
extern int close_service_fd(enum sfd_type type);
extern bool is_service_fd(int fd, enum sfd_type type);
extern bool is_any_service_fd(int fd);

int check_img_inventory(void);
int write_img_inventory(void);
void kill_inventory(void);

extern void print_data(unsigned long addr, unsigned char *data, size_t size);
extern void print_image_data(int fd, unsigned int length, int show);
extern struct cr_fd_desc_tmpl fdset_template[CR_FD_MAX];

extern int open_image_dir(void);
extern void close_image_dir(void);

int open_image_at(int dfd, int type, unsigned long flags, ...);
#define open_image(typ, flags, ...) open_image_at(get_service_fd(IMG_FD_OFF), typ, flags, ##__VA_ARGS__)
int open_pages_image(unsigned long flags, int pm_fd);
int open_pages_image_at(int dfd, unsigned long flags, int pm_fd);
void up_page_ids_base(void);

#define LAST_PID_PATH		"/proc/sys/kernel/ns_last_pid"
#define LAST_PID_PERM		0666

struct cr_fdset {
	int fd_off;
	int fd_nr;
	int *_fds;
};

static inline int fdset_fd(const struct cr_fdset *fdset, int type)
{
	int idx;

	idx = type - fdset->fd_off;
	BUG_ON(idx > fdset->fd_nr);

	return fdset->_fds[idx];
}

extern struct cr_fdset *glob_fdset;

int cr_dump_tasks(pid_t pid);
int cr_pre_dump_tasks(pid_t pid);
int cr_restore_tasks(void);
int cr_show(int pid);
int convert_to_elf(char *elf_path, int fd_core);
int cr_check(void);
int cr_exec(int pid, char **opts);

#define O_DUMP	(O_RDWR | O_CREAT | O_EXCL)
#define O_SHOW	(O_RDONLY)
#define O_RSTR	(O_RDONLY)

struct cr_fdset *cr_task_fdset_open(int pid, int mode);
struct cr_fdset *cr_ns_fdset_open(int pid, int mode);
struct cr_fdset *cr_glob_fdset_open(int mode);

void close_cr_fdset(struct cr_fdset **cr_fdset);

struct vm_area_list {
	struct list_head	h;
	unsigned		nr;
	unsigned long		priv_size; /* nr of pages in private VMAs */
	unsigned long		longest; /* nr of pages in longest VMA */
};

#define VM_AREA_LIST(name)	struct vm_area_list name = { .h = LIST_HEAD_INIT(name.h), .nr = 0, }

int collect_mappings(pid_t pid, struct vm_area_list *vma_area_list);
void free_mappings(struct vm_area_list *vma_area_list);
bool privately_dump_vma(struct vma_area *vma);

struct vma_area {
	struct list_head	list;
	VmaEntry		vma;

	union {
		int		vm_file_fd;
		int		vm_socket_id;
	};
	unsigned long		*page_bitmap;  /* existent pages */
	unsigned long		*ppage_bitmap; /* parent's existent pages */
};

#define vma_area_is(vma_area, s)	vma_entry_is(&((vma_area)->vma), s)
#define vma_area_len(vma_area)		vma_entry_len(&((vma_area)->vma))

struct fdt {
	int			nr;		/* How many tasks share this fd table */
	pid_t			pid;		/* Who should restore this fd table */
	/*
	 * The fd table is ready for restoing, if fdt_lock is equal to nr
	 * The fdt table was restrored, if fdt_lock is equal to nr + 1
	 */
	futex_t			fdt_lock;
};

struct rst_info {
	struct list_head	fds;
	struct list_head	eventpoll;
	struct list_head	tty_slaves;

	void			*premmapped_addr;
	unsigned long		premmapped_len;
	unsigned long		clone_flags;

	int			nr_zombies;

	int service_fd_id;
	struct fdt		*fdt;
};

static inline int in_vma_area(struct vma_area *vma, unsigned long addr)
{
	return addr >= (unsigned long)vma->vma.start &&
		addr < (unsigned long)vma->vma.end;
}

/*
 * When we have to restore a shared resource, we mush select which
 * task should do it, and make other(s) wait for it. In order to
 * avoid deadlocks, always make task with lower pid be the restorer.
 */
static inline bool pid_rst_prio(unsigned pid_a, unsigned pid_b)
{
	return pid_a < pid_b;
}

#endif /* __CR_CRTOOLS_H__ */
