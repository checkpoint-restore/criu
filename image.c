#include <unistd.h>
#include <stdarg.h>
#include <fcntl.h>
#include "crtools.h"
#include "cr_options.h"
#include "imgset.h"
#include "image.h"
#include "pstree.h"
#include "stats.h"
#include "cgroup.h"
#include "protobuf.h"
#include "protobuf/inventory.pb-c.h"
#include "protobuf/pagemap.pb-c.h"

bool fdinfo_per_id = false;
bool ns_per_id = false;
TaskKobjIdsEntry *root_ids;
u32 root_cg_set;

int check_img_inventory(void)
{
	int ret = -1;
	struct cr_img *img;
	InventoryEntry *he;

	img = open_image(CR_FD_INVENTORY, O_RSTR);
	if (!img)
		return -1;

	if (pb_read_one(img, &he, PB_INVENTORY) < 0)
		goto out_close;

	fdinfo_per_id = he->has_fdinfo_per_id ?  he->fdinfo_per_id : false;
	ns_per_id = he->has_ns_per_id ? he->ns_per_id : false;

	if (he->root_ids) {
		root_ids = xmalloc(sizeof(*root_ids));
		if (!root_ids)
			goto out_err;

		memcpy(root_ids, he->root_ids, sizeof(*root_ids));
	}

	if (he->has_root_cg_set) {
		if (he->root_cg_set == 0) {
			pr_err("Corrupted root cgset\n");
			goto out_err;
		}

		root_cg_set = he->root_cg_set;
	}

	if (he->img_version != CRTOOLS_IMAGES_V1) {
		pr_err("Not supported images version %u\n", he->img_version);
		goto out_err;
	}
	ret = 0;

out_err:
	inventory_entry__free_unpacked(he, NULL);
out_close:
	close_image(img);
	return ret;
}

int write_img_inventory(void)
{
	struct cr_img *img;
	InventoryEntry he = INVENTORY_ENTRY__INIT;
	struct {
		struct pstree_item i;
		struct dmp_info d;
	} crt = { };

	pr_info("Writing image inventory (version %u)\n", CRTOOLS_IMAGES_V1);

	img = open_image(CR_FD_INVENTORY, O_DUMP);
	if (!img)
		return -1;

	he.img_version = CRTOOLS_IMAGES_V1;
	he.fdinfo_per_id = true;
	he.has_fdinfo_per_id = true;
	he.ns_per_id = true;
	he.has_ns_per_id = true;

	crt.i.state = TASK_ALIVE;
	crt.i.pid.real = getpid();
	if (get_task_ids(&crt.i)) {
		close_image(img);
		return -1;
	}

	he.has_root_cg_set = true;
	if (dump_task_cgroup(NULL, &he.root_cg_set))
		return -1;

	he.root_ids = crt.i.ids;

	if (pb_write_one(img, &he, PB_INVENTORY) < 0)
		return -1;

	xfree(crt.i.ids);
	close_image(img);
	return 0;
}

void kill_inventory(void)
{
	unlinkat(get_service_fd(IMG_FD_OFF),
			imgset_template[CR_FD_INVENTORY].fmt, 0);
}

static struct cr_imgset *alloc_cr_imgset(int nr)
{
	struct cr_imgset *cr_imgset;
	unsigned int i;

	cr_imgset = xmalloc(sizeof(*cr_imgset));
	if (cr_imgset == NULL)
		return NULL;

	cr_imgset->_imgs = xmalloc(nr * sizeof(struct cr_img *));
	if (cr_imgset->_imgs == NULL) {
		xfree(cr_imgset);
		return NULL;
	}

	for (i = 0; i < nr; i++)
		cr_imgset->_imgs[i] = NULL;
	cr_imgset->fd_nr = nr;
	return cr_imgset;
}

static void __close_cr_imgset(struct cr_imgset *cr_imgset)
{
	unsigned int i;

	if (!cr_imgset)
		return;

	for (i = 0; i < cr_imgset->fd_nr; i++) {
		if (!cr_imgset->_imgs[i])
			continue;
		close_image(cr_imgset->_imgs[i]);
		cr_imgset->_imgs[i] = NULL;
	}
}

void close_cr_imgset(struct cr_imgset **cr_imgset)
{
	if (!cr_imgset || !*cr_imgset)
		return;

	__close_cr_imgset(*cr_imgset);

	xfree((*cr_imgset)->_imgs);
	xfree(*cr_imgset);
	*cr_imgset = NULL;
}

struct cr_imgset *cr_imgset_open_range(int pid, int from, int to,
			       unsigned long flags)
{
	struct cr_imgset *imgset;
	unsigned int i;

	imgset = alloc_cr_imgset(to - from);
	if (!imgset)
		goto err;

	from++;
	imgset->fd_off = from;
	for (i = from; i < to; i++) {
		struct cr_img *img;

		img = open_image(i, flags, pid);
		if (!img) {
			if (!(flags & O_CREAT))
				/* caller should check himself */
				continue;
			goto err;
		}

		imgset->_imgs[i - from] = img;
	}

	return imgset;

err:
	close_cr_imgset(&imgset);
	return NULL;
}

struct cr_imgset *cr_task_imgset_open(int pid, int mode)
{
	return cr_imgset_open(pid, TASK, mode);
}

struct cr_imgset *cr_glob_imgset_open(int mode)
{
	return cr_imgset_open(-1 /* ignored */, GLOB, mode);
}

struct cr_img *open_image_at(int dfd, int type, unsigned long flags, ...)
{
	struct cr_img *img;
	unsigned long oflags = flags;
	char path[PATH_MAX];
	va_list args;
	int ret;

	img = xmalloc(sizeof(*img));
	if (!img)
		goto errn;

	oflags |= imgset_template[type].oflags;
	flags &= ~(O_OPT | O_NOBUF);

	va_start(args, flags);
	vsnprintf(path, PATH_MAX, imgset_template[type].fmt, args);
	va_end(args);

	ret = openat(dfd, path, flags, CR_FD_PERM);
	if (ret < 0) {
		if ((oflags & O_OPT) && errno == ENOENT) {
			xfree(img);
			return NULL;
		}

		pr_perror("Unable to open %s", path);
		goto err;
	}

	img->_x.fd = ret;
	if (oflags & O_NOBUF)
		bfd_setraw(&img->_x);
	else if (bfdopen(&img->_x, flags))
		goto err;

	if (imgset_template[type].magic == RAW_IMAGE_MAGIC)
		goto skip_magic;

	if (flags == O_RDONLY) {
		u32 magic;

		if (read_img(img, &magic) < 0)
			goto err;
		if (magic != imgset_template[type].magic) {
			pr_err("Magic doesn't match for %s\n", path);
			goto err;
		}
	} else {
		if (write_img(img, &imgset_template[type].magic))
			goto err;
	}

skip_magic:
	return img;

err:
	xfree(img);
errn:
	return NULL;
}

void close_image(struct cr_img *img)
{
	bclose(&img->_x);
	xfree(img);
}

struct cr_img *img_from_fd(int fd)
{
	struct cr_img *img;

	img = xmalloc(sizeof(*img));
	if (img) {
		img->_x.fd = fd;
		bfd_setraw(&img->_x);
	}

	return img;
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
		ret = symlinkat(opts.img_parent, fd, CR_PARENT_LINK);
		if (ret < 0 && errno != EEXIST) {
			pr_perror("Can't link parent snapshot");
			goto err;
		}
	}

	return 0;

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

struct cr_img *open_pages_image_at(int dfd, unsigned long flags, struct cr_img *pmi)
{
	unsigned id;

	if (flags == O_RDONLY || flags == O_RDWR) {
		PagemapHead *h;
		if (pb_read_one(pmi, &h, PB_PAGEMAP_HEAD) < 0)
			return NULL;
		id = h->pages_id;
		pagemap_head__free_unpacked(h, NULL);
	} else {
		PagemapHead h = PAGEMAP_HEAD__INIT;
		id = h.pages_id = page_ids++;
		if (pb_write_one(pmi, &h, PB_PAGEMAP_HEAD) < 0)
			return NULL;
	}

	return open_image_at(dfd, CR_FD_PAGES, flags, id);
}

struct cr_img *open_pages_image(unsigned long flags, struct cr_img *pmi)
{
	return open_pages_image_at(get_service_fd(IMG_FD_OFF), flags, pmi);
}

/*
 * Write buffer @ptr of @size bytes into @fd file
 * Returns
 *	0  on success
 *	-1 on error (error message is printed)
 */
int write_img_buf(struct cr_img *img, const void *ptr, int size)
{
	int ret;

	ret = bwrite(&img->_x, ptr, size);
	if (ret == size)
		return 0;

	if (ret < 0)
		pr_perror("Can't write img file");
	else
		pr_err("Img trimmed %d/%d\n", ret, size);
	return -1;
}

/*
 * Read buffer @ptr of @size bytes from @fd file
 * Returns
 *	1  on success
 *	0  on EOF (silently)
 *	-1 on error (error message is printed)
 */
int read_img_buf_eof(struct cr_img *img, void *ptr, int size)
{
	int ret;

	ret = bread(&img->_x, ptr, size);
	if (ret == size)
		return 1;
	if (ret == 0)
		return 0;

	if (ret < 0)
		pr_perror("Can't read img file");
	else
		pr_err("Img trimmed %d/%d\n", ret, size);
	return -1;
}

/*
 * Read buffer @ptr of @size bytes from @fd file
 * Returns
 *	1  on success
 *	-1 on error or EOF (error message is printed)
 */
int read_img_buf(struct cr_img *img, void *ptr, int size)
{
	int ret;

	ret = read_img_buf_eof(img, ptr, size);
	if (ret == 0) {
		pr_err("Unexpected EOF\n");
		ret = -1;
	}

	return ret;
}

/*
 * read_img_str -- same as read_img_buf, but allocates memory for
 * the buffer and puts the '\0' at the end
 */

int read_img_str(struct cr_img *img, char **pstr, int size)
{
	int ret;
	char *str;

	str = xmalloc(size + 1);
	if (!str)
		return -1;

	ret = read_img_buf(img, str, size);
	if (ret < 0) {
		xfree(str);
		return -1;
	}

	str[size] = '\0';
	*pstr = str;
	return 0;
}

