#ifndef CRTOOLS_H_
#define CRTOOLS_H_

#include <sys/types.h>

#include "types.h"
#include "list.h"
#include "util.h"
#include "image.h"

extern void free_pstree(struct list_head *pstree_list);

#define CR_FD_PERM		(S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH)
#define CR_FD_PERM_DUMP		(S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH)

enum {
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
	_CR_FD_NS_TO,

	CR_FD_PSTREE,
	CR_FD_SHMEM_PAGES,
	CR_FD_GHOST_FILE,

	_CR_FD_GLOB_FROM,
	CR_FD_SK_QUEUES,
	CR_FD_REG_FILES,
	CR_FD_INETSK,
	CR_FD_UNIXSK,
	CR_FD_PIPES,
	CR_FD_PIPES_DATA,
	CR_FD_REMAP_FPATH,
	_CR_FD_GLOB_TO,

	CR_FD_MAX
};

struct cr_options {
	int			final_state;
	char			*show_dump_file;
	bool			leader_only;
	bool			show_pages_content;
	bool			restore_detach;
	bool			ext_unix_sk;
	bool			tcp_established_ok;
	unsigned int		namespaces_flags;
};

enum {
	LOG_FD_OFF = 1,
	IMG_FD_OFF,
	SELF_EXE_FD_OFF,
};

int get_service_fd(int type);

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
void show_pstree(int fd_pstree, struct cr_options *o);
void show_sigacts(int fd_sigacts, struct cr_options *o);
void show_itimers(int fd, struct cr_options *o);
void show_creds(int fd, struct cr_options *o);
void show_fs(int fd, struct cr_options *o);
void show_remap_files(int fd, struct cr_options *o);
void show_ghost_file(int fd, struct cr_options *o);
void show_fown_cont(fown_t *fown);

extern void print_data(unsigned long addr, unsigned char *data, size_t size);
extern struct cr_fd_desc_tmpl fdset_template[CR_FD_MAX];

#define FMT_FNAME_FDINFO	"fdinfo-%d.img"
#define FMT_FNAME_PAGES		"pages-%d.img"
#define FMT_FNAME_SHMEM_PAGES	"pages-shmem-%ld.img"
#define FMT_FNAME_REG_FILES	"reg-files.img"
#define FMT_FNAME_CORE		"core-%d.img"
#define FMT_FNAME_MM		"mm-%d.img"
#define FMT_FNAME_VMAS		"vmas-%d.img"
#define FMT_FNAME_PIPES		"pipes.img"
#define FMT_FNAME_PIPES_DATA	"pipes-data.img"
#define FMT_FNAME_PSTREE	"pstree.img"
#define FMT_FNAME_SIGACTS	"sigacts-%d.img"
#define FMT_FNAME_UNIXSK	"unixsk.img"
#define FMT_FNAME_INETSK	"inetsk.img"
#define FMT_FNAME_ITIMERS	"itimers-%d.img"
#define FMT_FNAME_CREDS		"creds-%d.img"
#define FMT_FNAME_UTSNS		"utsns-%d.img"
#define FMT_FNAME_IPCNS_VAR	"ipcns-var-%d.img"
#define FMT_FNAME_IPCNS_SHM	"ipcns-shm-%d.img"
#define FMT_FNAME_IPCNS_MSG	"ipcns-msg-%d.img"
#define FMT_FNAME_IPCNS_SEM	"ipcns-sem-%d.img"
#define FMT_FNAME_SK_QUEUES	"sk-queues.img"
#define FMT_FNAME_FS		"fs-%d.img"
#define FMT_FNAME_REMAP_FPATH	"remap-fpath.img"
#define FMT_FNAME_GHOST_FILE	"ghost-file-%x.img"

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
	struct vma_entry	vma;
	int			vm_file_fd;
};

#define vma_area_is(vma_area, s)	vma_entry_is(&((vma_area)->vma), s)
#define vma_area_len(vma_area)		vma_entry_len(&((vma_area)->vma))

struct rst_info {
	struct list_head	fds;
};

struct pstree_item {
	struct list_head	list;
	pid_t			pid;		/* leader pid */
	struct pstree_item	*parent;
	pid_t			pgid;
	pid_t			sid;
	int			state;		/* TASK_XXX constants */
	int			nr_children;	/* number of children */
	int			nr_threads;	/* number of threads */
	u32			*threads;	/* array of threads */
	u32			*children;	/* array of children */
	struct rst_info		*rst;
};

static inline int in_vma_area(struct vma_area *vma, unsigned long addr)
{
	return addr >= (unsigned long)vma->vma.start &&
		addr < (unsigned long)vma->vma.end;
}

#endif /* CRTOOLS_H_ */
