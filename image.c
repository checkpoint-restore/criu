#include <unistd.h>
#include <stdarg.h>
#include <fcntl.h>
#include "crtools.h"
#include "cr_options.h"
#include "fdset.h"
#include "image.h"
#include "pstree.h"
#include "stats.h"
#include "protobuf.h"
#include "protobuf/inventory.pb-c.h"
#include "protobuf/pagemap.pb-c.h"

bool fdinfo_per_id = false;
bool ns_per_id = false;
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
	ns_per_id = he->has_ns_per_id ? he->ns_per_id : false;

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
	he.ns_per_id = true;
	he.has_ns_per_id = true;

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

struct cr_fdset *cr_fdset_open_range(int pid, int from, int to,
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
	return cr_fdset_open(pid, TASK, mode);
}

struct cr_fdset *cr_glob_fdset_open(int mode)
{
	return cr_fdset_open(-1 /* ignored */, GLOB, mode);
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

int open_image_dir(char *dir)
{
	int fd, ret;

	fd = open(dir, O_RDONLY);
	if (fd < 0) {
		pr_perror("Can't open dir %s", dir);
		return -1;
	}

	ret = install_service_fd(IMG_FD_OFF, fd);
	close(fd);
	fd = ret;

	if (opts.img_parent) {
		int pfd;

		ret = symlinkat(opts.img_parent, fd, CR_PARENT_LINK);
		if (ret < 0) {
			pr_perror("Can't link parent snapshot");
			goto err;
		}

		pfd = openat(fd, CR_PARENT_LINK, O_RDONLY);
		if (pfd < 0) {
			pr_perror("Can't open parent snapshot");
			goto err;
		}

		ret = install_service_fd(PARENT_FD_OFF, pfd);

		close(pfd);
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

	if (flags == O_RDONLY || flags == O_RDWR) {
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
