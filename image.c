#include <unistd.h>
#include <stdarg.h>
#include "crtools.h"
#include "image.h"
#include "eventpoll.h"
#include "inotify.h"
#include "sockets.h"
#include "uts_ns.h"
#include "ipc_ns.h"
#include "sk-inet.h"
#include "mount.h"
#include "protobuf.h"
#include "protobuf/inventory.pb-c.h"

int check_img_inventory(void)
{
	int fd, ret;
	InventoryEntry *he;

	fd = open_image_ro(CR_FD_INVENTORY);
	if (fd < 0)
		return -1;

	ret = pb_read(fd, &he, inventory_entry);
	close(fd);
	if (ret < 0)
		return ret;

	ret = he->img_version;
	inventory_entry__free_unpacked(he, NULL);

	if (ret != CRTOOLS_IMAGES_V1) {
		pr_err("Not supported images version %u\n", ret);
		return -1;
	}

	return 0;
}

int write_img_inventory(void)
{
	int fd;
	InventoryEntry he = INVENTORY_ENTRY__INIT;

	pr_info("Writing image inventory (version %u)\n", CRTOOLS_IMAGES_V1);

	fd = open_image(CR_FD_INVENTORY, O_DUMP);
	if (fd < 0)
		return -1;

	he.img_version = CRTOOLS_IMAGES_V1;

	if (pb_write(fd, &he, inventory_entry) < 0)
		return -1;

	close(fd);
	return 0;
}

static void show_inventory(int fd, struct cr_options *o)
{
	InventoryEntry *he;

	if (pb_read(fd, &he, inventory_entry) < 0)
		return;

	pr_msg("Version: %u\n", he->img_version);
	inventory_entry__free_unpacked(he, NULL);
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

struct cr_fd_desc_tmpl fdset_template[CR_FD_MAX] = {
	FD_ENTRY(INVENTORY,	"inventory",	 show_inventory),
	FD_ENTRY(FDINFO,	"fdinfo-%d",	 show_files),
	FD_ENTRY(PAGES,		"pages-%d",	 show_pages),
	FD_ENTRY(SHMEM_PAGES,	"pages-shmem-%ld", show_pages),
	FD_ENTRY(REG_FILES,	"reg-files",	 show_reg_files),
	FD_ENTRY(EVENTFD,	"eventfd",	 show_eventfds),
	FD_ENTRY(EVENTPOLL,	"eventpoll",	 show_eventpoll),
	FD_ENTRY(EVENTPOLL_TFD,	"eventpoll-tfd", show_eventpoll_tfd),
	FD_ENTRY(INOTIFY,	"inotify",	 show_inotify),
	FD_ENTRY(INOTIFY_WD,	"inotify-wd",	 show_inotify_wd),
	FD_ENTRY(CORE,		"core-%d",	 show_core),
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

static int image_dir_fd = -1;

int open_image(int type, unsigned long flags, ...)
{
	char path[PATH_MAX];
	va_list args;
	int ret;

	va_start(args, flags);
	vsnprintf(path, PATH_MAX, fdset_template[type].fmt, args);
	va_end(args);

	if (flags & O_EXCL) {
		ret = unlinkat(image_dir_fd, path, 0);
		if (ret && errno != ENOENT) {
			pr_perror("Unable to unlink %s", path);
			goto err;
		}
	}

	ret = openat(image_dir_fd, path, flags, CR_FD_PERM);
	if (ret < 0) {
		pr_perror("Unable to open %s", path);
		goto err;
	}

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

	return ret;
err:
	return -1;
}

int open_image_dir(void)
{
	int fd;

	image_dir_fd = get_service_fd(IMG_FD_OFF);
	if (image_dir_fd < 0) {
		pr_perror("Can't get image fd");
		return -1;
	}

	fd = open(".", O_RDONLY);
	if (fd < 0) {
		pr_perror("Can't open cwd");
		return -1;
	}

	pr_info("Image dir fd is %d\n", image_dir_fd);

	return reopen_fd_as(image_dir_fd, fd);
}

void close_image_dir(void)
{
	close(image_dir_fd);
	image_dir_fd = -1;
}
