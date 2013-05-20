#include <unistd.h>
#include <stdarg.h>
#include "crtools.h"
#include "image.h"
#include "eventpoll.h"
#include "signalfd.h"
#include "fsnotify.h"
#include "sockets.h"
#include "uts_ns.h"
#include "ipc_ns.h"
#include "sk-inet.h"
#include "sk-packet.h"
#include "mount.h"
#include "net.h"
#include "pstree.h"
#include "stats.h"
#include "protobuf.h"
#include "protobuf/inventory.pb-c.h"
#include "protobuf/pagemap.pb-c.h"

bool fdinfo_per_id = false;
TaskKobjIdsEntry *root_ids;

int check_img_inventory(void)
{
	int fd, ret = -1;
	InventoryEntry *he;

	fd = open_image(CR_FD_INVENTORY, O_RSTR);
	if (fd < 0)
		return -1;

	if (pb_read_one(fd, &he, PB_INVENTORY) < 0)
		goto out_close;

	fdinfo_per_id = he->has_fdinfo_per_id ?  he->fdinfo_per_id : false;

	if (he->root_ids) {
		root_ids = xmalloc(sizeof(*root_ids));
		if (!root_ids)
			goto out_err;

		memcpy(root_ids, he->root_ids, sizeof(*root_ids));
	}

	if (he->img_version != CRTOOLS_IMAGES_V1) {
		pr_err("Not supported images version %u\n", he->img_version);
		goto out_err;
	}
	ret = 0;

out_err:
	inventory_entry__free_unpacked(he, NULL);
out_close:
	close(fd);
	return ret;
}

int write_img_inventory(void)
{
	int fd;
	InventoryEntry he = INVENTORY_ENTRY__INIT;
	struct pstree_item crt = { };

	pr_info("Writing image inventory (version %u)\n", CRTOOLS_IMAGES_V1);

	fd = open_image(CR_FD_INVENTORY, O_DUMP);
	if (fd < 0)
		return -1;

	he.img_version = CRTOOLS_IMAGES_V1;
	he.fdinfo_per_id = true;
	he.has_fdinfo_per_id = true;

	crt.state = TASK_ALIVE;
	crt.pid.real = getpid();
	if (get_task_ids(&crt)){
		close(fd);
		return -1;
	}

	he.root_ids = crt.ids;

	if (pb_write_one(fd, &he, PB_INVENTORY) < 0)
		return -1;

	xfree(crt.ids);
	close(fd);
	return 0;
}

void kill_inventory(void)
{
	unlinkat(get_service_fd(IMG_FD_OFF),
			fdset_template[CR_FD_INVENTORY].fmt, 0);
}

static void show_inventory(int fd)
{
	pb_show_vertical(fd, PB_INVENTORY);
}

/*
 * The cr fd set is the set of files where the information
 * about dumped processes is stored. Each file carries some
 * small portion of info about the whole picture, see below
 * for more details.
 */

#define FD_ENTRY(_name, _fmt, _show)		\
	[CR_FD_##_name] = {			\
		.fmt	= _fmt ".img",		\
		.magic	= _name##_MAGIC,	\
		.show	= _show,		\
	}

static void show_raw_image(int fd) {};

struct cr_fd_desc_tmpl fdset_template[CR_FD_MAX] = {
	FD_ENTRY(INVENTORY,	"inventory",	 show_inventory),
	FD_ENTRY(FDINFO,	"fdinfo-%d",	 show_files),
	FD_ENTRY(PAGEMAP,	"pagemap-%ld",	 show_pagemap),
	FD_ENTRY(SHMEM_PAGEMAP,	"pagemap-shmem-%ld", show_pagemap),
	FD_ENTRY(REG_FILES,	"reg-files",	 show_reg_files),
	FD_ENTRY(NS_FILES,	"ns-files",	 show_ns_files),
	FD_ENTRY(EVENTFD,	"eventfd",	 show_eventfds),
	FD_ENTRY(EVENTPOLL,	"eventpoll",	 show_eventpoll),
	FD_ENTRY(EVENTPOLL_TFD,	"eventpoll-tfd", show_eventpoll_tfd),
	FD_ENTRY(SIGNALFD,	"signalfd",	 show_signalfd),
	FD_ENTRY(INOTIFY,	"inotify",	 show_inotify),
	FD_ENTRY(INOTIFY_WD,	"inotify-wd",	 show_inotify_wd),
	FD_ENTRY(FANOTIFY,	"fanotify",	 show_fanotify),
	FD_ENTRY(FANOTIFY_MARK,	"fanotify-mark", show_fanotify_mark),
	FD_ENTRY(CORE,		"core-%d",	 show_core),
	FD_ENTRY(IDS,		"ids-%d",	 show_ids),
	FD_ENTRY(MM,		"mm-%d",	 show_mm),
	FD_ENTRY(VMAS,		"vmas-%d",	 show_vmas),
	FD_ENTRY(PIPES,		"pipes",	 show_pipes),
	FD_ENTRY(PIPES_DATA,	"pipes-data",	 show_pipes_data),
	FD_ENTRY(FIFO,		"fifo",		 show_fifo),
	FD_ENTRY(FIFO_DATA,	"fifo-data",	 show_fifo_data),
	FD_ENTRY(PSTREE,	"pstree",	 show_pstree),
	FD_ENTRY(SIGACT,	"sigacts-%d",	 show_sigacts),
	FD_ENTRY(UNIXSK,	"unixsk",	 show_unixsk),
	FD_ENTRY(INETSK,	"inetsk",	 show_inetsk),
	FD_ENTRY(PACKETSK,	"packetsk",	 show_packetsk),
	FD_ENTRY(NETLINKSK,	"netlinksk",	 show_netlinksk),
	FD_ENTRY(SK_QUEUES,	"sk-queues",	 show_sk_queues),
	FD_ENTRY(ITIMERS,	"itimers-%d",	 show_itimers),
	FD_ENTRY(CREDS,		"creds-%d",	 show_creds),
	FD_ENTRY(UTSNS,		"utsns-%d",	 show_utsns),
	FD_ENTRY(IPCNS_VAR,	"ipcns-var-%d",	 show_ipc_var),
	FD_ENTRY(IPCNS_SHM,	"ipcns-shm-%d",	 show_ipc_shm),
	FD_ENTRY(IPCNS_MSG,	"ipcns-msg-%d",	 show_ipc_msg),
	FD_ENTRY(IPCNS_SEM,	"ipcns-sem-%d",	 show_ipc_sem),
	FD_ENTRY(FS,		"fs-%d",	 show_fs),
	FD_ENTRY(REMAP_FPATH,	"remap-fpath",	 show_remap_files),
	FD_ENTRY(GHOST_FILE,	"ghost-file-%x", show_ghost_file),
	FD_ENTRY(TCP_STREAM,	"tcp-stream-%x", show_tcp_stream),
	FD_ENTRY(MOUNTPOINTS,	"mountpoints-%d", show_mountpoints),
	FD_ENTRY(NETDEV,	"netdev-%d",	 show_netdevices),
	FD_ENTRY(IFADDR,	"ifaddr-%d",	 show_raw_image),
	FD_ENTRY(ROUTE,		"route-%d",	 show_raw_image),
	FD_ENTRY(TMPFS,		"tmpfs-%d.tar.gz", show_raw_image),
	FD_ENTRY(TTY,		"tty",		 show_tty),
	FD_ENTRY(TTY_INFO,	"tty-info",	 show_tty_info),
	FD_ENTRY(FILE_LOCKS,	"filelocks-%d",	 show_file_locks),
	FD_ENTRY(RLIMIT,	"rlimit-%d",	 show_rlimit),
	FD_ENTRY(PAGES,		"pages-%u",	 NULL),
	FD_ENTRY(PAGES_OLD,	"pages-%d",	 NULL),
	FD_ENTRY(SHM_PAGES_OLD, "pages-shmem-%ld", NULL),
	FD_ENTRY(SIGNAL,	"signal-s-%d",	 show_siginfo), /* shared signals */
	FD_ENTRY(PSIGNAL,	"signal-p-%d",	 show_siginfo), /* private signals */

	[CR_FD_STATS] = {
		.fmt = "stats-%s",
		.magic = STATS_MAGIC,
		.show = show_stats,
	},
};

static struct cr_fdset *alloc_cr_fdset(int nr)
{
	struct cr_fdset *cr_fdset;
	unsigned int i;

	cr_fdset = xmalloc(sizeof(*cr_fdset));
	if (cr_fdset == NULL)
		return NULL;

	cr_fdset->_fds = xmalloc(nr * sizeof(int));
	if (cr_fdset->_fds == NULL) {
		xfree(cr_fdset);
		return NULL;
	}

	for (i = 0; i < nr; i++)
		cr_fdset->_fds[i] = -1;
	cr_fdset->fd_nr = nr;
	return cr_fdset;
}

static void __close_cr_fdset(struct cr_fdset *cr_fdset)
{
	unsigned int i;

	if (!cr_fdset)
		return;

	for (i = 0; i < cr_fdset->fd_nr; i++) {
		if (cr_fdset->_fds[i] == -1)
			continue;
		close_safe(&cr_fdset->_fds[i]);
		cr_fdset->_fds[i] = -1;
	}
}

void close_cr_fdset(struct cr_fdset **cr_fdset)
{
	if (!cr_fdset || !*cr_fdset)
		return;

	__close_cr_fdset(*cr_fdset);

	xfree((*cr_fdset)->_fds);
	xfree(*cr_fdset);
	*cr_fdset = NULL;
}

static struct cr_fdset *cr_fdset_open(int pid, int from, int to,
			       unsigned long flags)
{
	struct cr_fdset *fdset;
	unsigned int i;
	int ret = -1;

	fdset = alloc_cr_fdset(to - from);
	if (!fdset)
		goto err;

	from++;
	fdset->fd_off = from;
	for (i = from; i < to; i++) {
		ret = open_image(i, flags, pid);
		if (ret < 0) {
			if (!(flags & O_CREAT))
				/* caller should check himself */
				continue;
			goto err;
		}

		fdset->_fds[i - from] = ret;
	}

	return fdset;

err:
	close_cr_fdset(&fdset);
	return NULL;
}

struct cr_fdset *cr_task_fdset_open(int pid, int mode)
{
	return cr_fdset_open(pid, _CR_FD_TASK_FROM, _CR_FD_TASK_TO, mode);
}

struct cr_fdset *cr_ns_fdset_open(int pid, int mode)
{
	return cr_fdset_open(pid, _CR_FD_NS_FROM, _CR_FD_NS_TO, mode);
}

struct cr_fdset *cr_glob_fdset_open(int mode)
{
	return cr_fdset_open(-1 /* ignored */, _CR_FD_GLOB_FROM, _CR_FD_GLOB_TO, mode);
}

int open_image_at(int dfd, int type, unsigned long flags, ...)
{
	char path[PATH_MAX];
	va_list args;
	int ret;

	va_start(args, flags);
	vsnprintf(path, PATH_MAX, fdset_template[type].fmt, args);
	va_end(args);

	if (flags & O_EXCL) {
		ret = unlinkat(dfd, path, 0);
		if (ret && errno != ENOENT) {
			pr_perror("Unable to unlink %s", path);
			goto err;
		}
	}

	ret = openat(dfd, path, flags, CR_FD_PERM);
	if (ret < 0) {
		pr_perror("Unable to open %s", path);
		goto err;
	}

	if (fdset_template[type].magic == RAW_IMAGE_MAGIC)
		goto skip_magic;

	if (flags == O_RDONLY) {
		u32 magic;

		if (read_img(ret, &magic) < 0)
			goto err;
		if (magic != fdset_template[type].magic) {
			pr_err("Magic doesn't match for %s\n", path);
			goto err;
		}
	} else {
		if (write_img(ret, &fdset_template[type].magic))
			goto err;
	}

skip_magic:
	return ret;
err:
	return -1;
}

int open_image_dir(void)
{
	int fd, ret;

	fd = open(".", O_RDONLY);
	if (fd < 0) {
		pr_perror("Can't open cwd");
		return -1;
	}

	ret = install_service_fd(IMG_FD_OFF, fd);

	close(fd);

	if (opts.img_parent) {
		ret = symlink(opts.img_parent, CR_PARENT_LINK);
		if (ret < 0) {
			pr_perror("Can't link parent snapshot.");
			goto err;
		}

		fd = open(CR_PARENT_LINK, O_RDONLY);
		if (fd < 0) {
			pr_perror("Can't open parent snapshot.");
			goto err;
		}

		ret = install_service_fd(PARENT_FD_OFF, fd);

		close(fd);
	}

	return ret;

err:
	close_image_dir();
	return -1;
}

void close_image_dir(void)
{
	close_service_fd(IMG_FD_OFF);
}

static unsigned long page_ids = 1;

void up_page_ids_base(void)
{
	/*
	 * When page server and criu dump work on
	 * the same dir, the shmem pagemaps and regular
	 * pagemaps may have IDs conflicts. Fix this by
	 * making page server produce page images with
	 * higher IDs.
	 */

	BUG_ON(page_ids != 1);
	page_ids += 0x10000;
}

int open_pages_image_at(int dfd, unsigned long flags, int pm_fd)
{
	unsigned id;

	if (flags == O_RDONLY) {
		PagemapHead *h;
		if (pb_read_one(pm_fd, &h, PB_PAGEMAP_HEAD) < 0)
			return -1;
		id = h->pages_id;
		pagemap_head__free_unpacked(h, NULL);
	} else {
		PagemapHead h = PAGEMAP_HEAD__INIT;
		id = h.pages_id = page_ids++;
		if (pb_write_one(pm_fd, &h, PB_PAGEMAP_HEAD) < 0)
			return -1;
	}

	return open_image_at(dfd, CR_FD_PAGES, flags, id);
}

int open_pages_image(unsigned long flags, int pm_fd)
{
	return open_pages_image_at(get_service_fd(IMG_FD_OFF), flags, pm_fd);
}
