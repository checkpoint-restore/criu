#ifndef CRTOOLS_H_
#define CRTOOLS_H_

#include <sys/types.h>

#include "list.h"
#include "types.h"
#include "list.h"
#include "util.h"
#include "image.h"

#include "../protobuf/vma.pb-c.h"

#define CR_FD_PERM		(S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH)
#define CR_FD_PERM_DUMP		(S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH)

#define CRIU_VERSION_MAJOR	0
#define CRIU_VERSION_MINOR	3

enum {
	CR_FD_INVENTORY,
	/*
	 * Task entries
	 */

	_CR_FD_TASK_FROM,
	CR_FD_FDINFO,
	CR_FD_PAGES,
	CR_FD_CORE,
	CR_FD_MM,
	CR_FD_VMAS,
	CR_FD_SIGACT,
	CR_FD_ITIMERS,
	CR_FD_CREDS,
	CR_FD_FS,
	_CR_FD_TASK_TO,

	/*
	 * NS entries
	 */

	_CR_FD_NS_FROM,
	CR_FD_UTSNS,
	CR_FD_IPCNS_VAR,
	CR_FD_IPCNS_SHM,
	CR_FD_IPCNS_MSG,
	CR_FD_IPCNS_SEM,
	CR_FD_MOUNTPOINTS,
	CR_FD_NETDEV,
	CR_FD_IFADDR,
	CR_FD_ROUTE,
	_CR_FD_NS_TO,

	CR_FD_PSTREE,
	CR_FD_SHMEM_PAGES,
	CR_FD_GHOST_FILE,
	CR_FD_TCP_STREAM,

	_CR_FD_GLOB_FROM,
	CR_FD_SK_QUEUES,
	CR_FD_REG_FILES,
	CR_FD_INETSK,
	CR_FD_UNIXSK,
	CR_FD_PACKETSK,
	CR_FD_PIPES,
	CR_FD_PIPES_DATA,
	CR_FD_FIFO,
	CR_FD_FIFO_DATA,
	CR_FD_TTY,
	CR_FD_TTY_INFO,
	CR_FD_REMAP_FPATH,
	CR_FD_EVENTFD,
	CR_FD_EVENTPOLL,
	CR_FD_EVENTPOLL_TFD,
	CR_FD_SIGNALFD,
	CR_FD_INOTIFY,
	CR_FD_INOTIFY_WD,
	_CR_FD_GLOB_TO,

	CR_FD_TMPFS,

	CR_FD_MAX
};

struct script {
	struct list_head node;
	char *path;
};

struct cr_options {
	int			final_state;
	char			*show_dump_file;
	bool			show_pages_content;
	bool			restore_detach;
	bool			ext_unix_sk;
	bool			shell_job;
	bool			tcp_established_ok;
	bool			evasive_devices;
	bool			link_remap_ok;
	unsigned int		namespaces_flags;
	bool			log_file_per_pid;
	char			*output;
	char			*root;
	char			*pidfile;
	struct list_head	veth_pairs;
	struct list_head	scripts;
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

	SERVICE_FD_MAX
};

extern int init_service_fd(void);
extern int get_service_fd(enum sfd_type type);
extern bool is_service_fd(int fd, enum sfd_type type);
extern bool is_any_service_fd(int fd);

/* file descriptors template */
struct cr_fd_desc_tmpl {
	const char	*fmt;			/* format for the name */
	u32		magic;			/* magic in the header */
	void		(*show)(int fd, struct cr_options *o);
};

void show_files(int fd_files, struct cr_options *o);
void show_pages(int fd_pages, struct cr_options *o);
void show_reg_files(int fd_reg_files, struct cr_options *o);
void show_core(int fd_core, struct cr_options *o);
void show_mm(int fd_mm, struct cr_options *o);
void show_vmas(int fd_vma, struct cr_options *o);
void show_pipes(int fd_pipes, struct cr_options *o);
void show_pipes_data(int fd_pipes, struct cr_options *o);
void show_fifo(int fd, struct cr_options *o);
void show_fifo_data(int fd_pipes, struct cr_options *o);
void show_pstree(int fd_pstree, struct cr_options *o);
void show_sigacts(int fd_sigacts, struct cr_options *o);
void show_itimers(int fd, struct cr_options *o);
void show_creds(int fd, struct cr_options *o);
void show_fs(int fd, struct cr_options *o);
void show_remap_files(int fd, struct cr_options *o);
void show_ghost_file(int fd, struct cr_options *o);
void show_fown_cont(void *p);
void show_eventfds(int fd, struct cr_options *o);
void show_tty(int fd, struct cr_options *o);
void show_tty_info(int fd, struct cr_options *o);

int check_img_inventory(void);
int write_img_inventory(void);

extern void print_data(unsigned long addr, unsigned char *data, size_t size);
extern void print_image_data(int fd, unsigned int length, int show);
extern struct cr_fd_desc_tmpl fdset_template[CR_FD_MAX];

extern int open_image_dir(void);
extern void close_image_dir(void);

int open_image(int type, unsigned long flags, ...);
#define open_image_ro(type, ...) open_image(type, O_RDONLY, ##__VA_ARGS__)

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
extern struct cr_options opts;

int cr_dump_tasks(pid_t pid, const struct cr_options *opts);
int cr_restore_tasks(pid_t pid, struct cr_options *opts);
int cr_show(struct cr_options *opts);
int convert_to_elf(char *elf_path, int fd_core);
int cr_check(void);

#define O_DUMP	(O_RDWR | O_CREAT | O_EXCL)
#define O_SHOW	(O_RDONLY)

struct cr_fdset *cr_task_fdset_open(int pid, int mode);
struct cr_fdset *cr_ns_fdset_open(int pid, int mode);
struct cr_fdset *cr_glob_fdset_open(int mode);

void close_cr_fdset(struct cr_fdset **cr_fdset);

void free_mappings(struct list_head *vma_area_list);

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

struct rst_info {
	struct list_head	fds;
	struct list_head	eventpoll;
	struct list_head	tty_slaves;

	void			*premmapped_addr;
	unsigned long		premmapped_len;
};

static inline int in_vma_area(struct vma_area *vma, unsigned long addr)
{
	return addr >= (unsigned long)vma->vma.start &&
		addr < (unsigned long)vma->vma.end;
}

#endif /* CRTOOLS_H_ */
