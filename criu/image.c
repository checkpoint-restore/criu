#include <stdio.h>
#include <unistd.h>
#include <stdarg.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/stat.h>
#include "crtools.h"
#include "cr_options.h"
#include "imgset.h"
#include "image.h"
#include "pstree.h"
#include "stats.h"
#include "cgroup.h"
#include "lsm.h"
#include "protobuf.h"
#include "xmalloc.h"
#include "images/inventory.pb-c.h"
#include "images/pagemap.pb-c.h"
#include "proc_parse.h"
#include "img-streamer.h"
#include "namespaces.h"

bool ns_per_id = false;
bool img_common_magic = true;
TaskKobjIdsEntry *root_ids;
u32 root_cg_set;
Lsmtype image_lsm;

int check_img_inventory(bool restore)
{
	int ret = -1;
	struct cr_img *img;
	InventoryEntry *he;

	img = open_image(CR_FD_INVENTORY, O_RSTR);
	if (!img)
		return -1;

	if (pb_read_one(img, &he, PB_INVENTORY) < 0)
		goto out_close;

	if (!he->has_fdinfo_per_id || !he->fdinfo_per_id) {
		pr_err("Too old image, no longer supported\n");
		goto out_close;
	}

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

	if (he->has_lsmtype)
		image_lsm = he->lsmtype;
	else
		image_lsm = LSMTYPE__NO_LSM;

	switch (he->img_version) {
	case CRTOOLS_IMAGES_V1:
		/* good old images. OK */
		img_common_magic = false;
		break;
	case CRTOOLS_IMAGES_V1_1:
		/* newer images with extra magic in the head */
		break;
	default:
		pr_err("Not supported images version %u\n", he->img_version);
		goto out_err;
	}

	if (restore && he->tcp_close && !opts.tcp_close) {
		pr_err("Need to set the --tcp-close options.\n");
		goto out_err;
	}

	ret = 0;

out_err:
	inventory_entry__free_unpacked(he, NULL);
out_close:
	close_image(img);
	return ret;
}

int write_img_inventory(InventoryEntry *he)
{
	struct cr_img *img;
	int ret;

	pr_info("Writing image inventory (version %u)\n", CRTOOLS_IMAGES_V1);

	img = open_image(CR_FD_INVENTORY, O_DUMP);
	if (!img)
		return -1;

	ret = pb_write_one(img, he, PB_INVENTORY);

	xfree(he->root_ids);
	close_image(img);
	if (ret < 0)
		return -1;
	return 0;
}

int inventory_save_uptime(InventoryEntry *he)
{
	if (!opts.track_mem)
		return 0;

	/*
	 * dump_uptime is used to detect whether a process was handled
	 * before or it is a new process with the same pid.
	 */
	if (parse_uptime(&he->dump_uptime))
		return -1;

	he->has_dump_uptime = true;
	return 0;
}

/*
 * This function is intended to get an inventory image from previous (parent)
 * dump iteration. We use dump_uptime from the image in detect_pid_reuse().
 *
 * You see that these function never fails by itself, it only prints warnings
 * to better understand reasons why we don't found a proper image, failing here
 * is too early. We get to detect_pid_reuse() only if we have a parent pagemap
 * and that's the proper place to fail: we know that there is a parent pagemap
 * but we don't have (can't access, etc) parent inventory => can't detect
 * pid-reuse => fail.
 */

InventoryEntry *get_parent_inventory(void)
{
	struct cr_img *img;
	InventoryEntry *ie;
	int dir;

	dir = openat(get_service_fd(IMG_FD_OFF), CR_PARENT_LINK, O_RDONLY);
	if (dir == -1) {
		/*
		 * We print the warning below to be notified that we had some
		 * unexpected problem on open. For instance we have a parent
		 * directory but have no access. Having no parent inventory
		 * when also having no parent directory is an expected case of
		 * first dump iteration.
		 */
		if (errno != ENOENT)
			pr_warn("Failed to open parent directory\n");
		return NULL;
	}

	img = open_image_at(dir, CR_FD_INVENTORY, O_RSTR);
	if (!img) {
		pr_warn("Failed to open parent pre-dump inventory image\n");
		close(dir);
		return NULL;
	}

	if (pb_read_one(img, &ie, PB_INVENTORY) < 0) {
		pr_warn("Failed to read parent pre-dump inventory entry\n");
		close_image(img);
		close(dir);
		return NULL;
	}

	if (!ie->has_dump_uptime) {
		pr_warn("Parent pre-dump inventory has no uptime\n");
		inventory_entry__free_unpacked(ie, NULL);
		ie = NULL;
	}

	close_image(img);
	close(dir);
	return ie;
}

int prepare_inventory(InventoryEntry *he)
{
	struct pid pid;
	struct {
		struct pstree_item i;
		struct dmp_info d;
	} crt = { .i.pid = &pid };

	pr_info("Preparing image inventory (version %u)\n", CRTOOLS_IMAGES_V1);

	he->img_version = CRTOOLS_IMAGES_V1_1;
	he->fdinfo_per_id = true;
	he->has_fdinfo_per_id = true;
	he->ns_per_id = true;
	he->has_ns_per_id = true;
	he->has_lsmtype = true;
	he->lsmtype = host_lsm_type();

	crt.i.pid->state = TASK_ALIVE;
	crt.i.pid->real = getpid();
	if (get_task_ids(&crt.i))
		return -1;

	he->has_root_cg_set = true;
	if (dump_task_cgroup(NULL, &he->root_cg_set, NULL))
		return -1;

	he->root_ids = crt.i.ids;

	/* tcp_close has to be set on restore if it has been set on dump. */
	if (opts.tcp_close) {
		he->tcp_close = true;
		he->has_tcp_close = true;
	}

	return 0;
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

static int do_open_image(struct cr_img *img, int dfd, int type, unsigned long flags, char *path);

struct cr_img *open_image_at(int dfd, int type, unsigned long flags, ...)
{
	struct cr_img *img;
	unsigned long oflags;
	char path[PATH_MAX];
	va_list args;
	bool lazy = false;

	if (dfd == -1) {
		dfd = get_service_fd(IMG_FD_OFF);
		lazy = (flags & O_CREAT);
	}

	img = xmalloc(sizeof(*img));
	if (!img)
		return NULL;

	oflags = flags | imgset_template[type].oflags;

	va_start(args, flags);
	vsnprintf(path, PATH_MAX, imgset_template[type].fmt, args);
	va_end(args);

	if (lazy) {
		img->fd = LAZY_IMG_FD;
		img->type = type;
		img->oflags = oflags;
		img->path = xstrdup(path);
		return img;
	} else
		img->fd = EMPTY_IMG_FD;

	if (do_open_image(img, dfd, type, oflags, path)) {
		close_image(img);
		return NULL;
	}

	return img;
}

static inline u32 head_magic(int oflags)
{
	return oflags & O_SERVICE ? IMG_SERVICE_MAGIC : IMG_COMMON_MAGIC;
}

static int img_check_magic(struct cr_img *img, int oflags, int type, char *path)
{
	u32 magic;

	if (read_img(img, &magic) < 0)
		return -1;

	if (img_common_magic && (type != CR_FD_INVENTORY)) {
		if (magic != head_magic(oflags)) {
			pr_err("Head magic doesn't match for %s\n", path);
			return -1;
		}

		if (read_img(img, &magic) < 0)
			return -1;
	}

	if (magic != imgset_template[type].magic) {
		pr_err("Magic doesn't match for %s\n", path);
		return -1;
	}

	return 0;
}

static int img_write_magic(struct cr_img *img, int oflags, int type)
{
	if (img_common_magic && (type != CR_FD_INVENTORY)) {
		u32 cmagic;

		cmagic = head_magic(oflags);
		if (write_img(img, &cmagic))
			return -1;
	}

	return write_img(img, &imgset_template[type].magic);
}

struct openat_args {
	char	path[PATH_MAX];
	int	flags;
	int	err;
	int	mode;
};

static int userns_openat(void *arg, int dfd, int pid)
{
	struct openat_args *pa = (struct openat_args *)arg;
	int ret;

	ret = openat(dfd, pa->path, pa->flags, pa->mode);
	if (ret < 0)
		pa->err = errno;

	return ret;
}

static int do_open_image(struct cr_img *img, int dfd, int type, unsigned long oflags, char *path)
{
	int ret, flags;

	flags = oflags & ~(O_NOBUF | O_SERVICE | O_FORCE_LOCAL);

	if (opts.stream && !(oflags & O_FORCE_LOCAL)) {
		ret = img_streamer_open(path, flags);
		errno = EIO; /* errno value is meaningless, only the ret value is meaningful */
	} else if (root_ns_mask & CLONE_NEWUSER &&
		   type == CR_FD_PAGES && oflags & O_RDWR) {
		/*
		 * For pages images dedup we need to open images read-write on
		 * restore, that may require proper capabilities, so we ask
		 * usernsd to do it for us
		 */
		struct openat_args pa = {
			.flags = flags,
			.err = 0,
			.mode = CR_FD_PERM,
		};
		snprintf(pa.path, PATH_MAX, "%s", path);
		ret = userns_call(userns_openat, UNS_FDOUT, &pa, sizeof(struct openat_args), dfd);
		if (ret < 0)
			errno = pa.err;
	} else
		ret = openat(dfd, path, flags, CR_FD_PERM);
	if (ret < 0) {
		if (!(flags & O_CREAT) && (errno == ENOENT || ret == -ENOENT)) {
			pr_info("No %s image\n", path);
			img->_x.fd = EMPTY_IMG_FD;
			goto skip_magic;
		}

		pr_perror("Unable to open %s", path);
		goto err;
	}

	img->_x.fd = ret;
	if (oflags & O_NOBUF)
		bfd_setraw(&img->_x);
	else {
		if (flags == O_RDONLY)
			ret = bfdopenr(&img->_x);
		else
			ret = bfdopenw(&img->_x);

		if (ret)
			goto err;
	}

	if (imgset_template[type].magic == RAW_IMAGE_MAGIC)
		goto skip_magic;

	if (flags == O_RDONLY)
		ret = img_check_magic(img, oflags, type, path);
	else
		ret = img_write_magic(img, oflags, type);
	if (ret)
		goto err;

skip_magic:
	return 0;

err:
	return -1;
}

int open_image_lazy(struct cr_img *img)
{
	int dfd;
	char *path = img->path;

	img->path = NULL;

	dfd = get_service_fd(IMG_FD_OFF);
	if (do_open_image(img, dfd, img->type, img->oflags, path)) {
		xfree(path);
		return -1;
	}

	xfree(path);
	return 0;
}

void close_image(struct cr_img *img)
{
	if (lazy_image(img)) {
		/*
		 * Remove the image file if it's there so that
		 * subsequent restore doesn't read wrong or fake
		 * data from it.
		 */
		unlinkat(get_service_fd(IMG_FD_OFF), img->path, 0);
		xfree(img->path);
	} else if (!empty_image(img))
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

/*
 * `mode` should be O_RSTR or O_DUMP depending on the intent.
 * This is used when opts.stream is enabled for picking the right streamer
 * socket name. `mode` is ignored when opts.stream is not enabled.
 */
int open_image_dir(char *dir, int mode)
{
	int fd, ret;

	fd = open(dir, O_RDONLY);
	if (fd < 0) {
		pr_perror("Can't open dir %s", dir);
		return -1;
	}

	ret = install_service_fd(IMG_FD_OFF, fd);
	if (ret < 0) {
		pr_err("install_service_fd failed.\n");
		return -1;
	}
	fd = ret;

	if (opts.stream) {
		if (img_streamer_init(dir, mode) < 0)
			goto err;
	} else if (opts.img_parent) {
		ret = symlinkat(opts.img_parent, fd, CR_PARENT_LINK);
		if (ret < 0 && errno != EEXIST) {
			pr_perror("Can't link parent snapshot");
			goto err;
		}

		if (opts.img_parent[0] == '/')
			pr_warn("Absolute paths for parent links "
					"may not work on restore!\n");
	}

	return 0;

err:
	close_image_dir();
	return -1;
}

void close_image_dir(void)
{
	if (opts.stream)
		img_streamer_finish();
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

struct cr_img *open_pages_image_at(int dfd, unsigned long flags, struct cr_img *pmi, u32 *id)
{
	if (flags == O_RDONLY || flags == O_RDWR) {
		PagemapHead *h;
		if (pb_read_one(pmi, &h, PB_PAGEMAP_HEAD) < 0)
			return NULL;
		*id = h->pages_id;
		pagemap_head__free_unpacked(h, NULL);
	} else {
		PagemapHead h = PAGEMAP_HEAD__INIT;
		*id = h.pages_id = page_ids++;
		if (pb_write_one(pmi, &h, PB_PAGEMAP_HEAD) < 0)
			return NULL;
	}

	return open_image_at(dfd, CR_FD_PAGES, flags, *id);
}

struct cr_img *open_pages_image(unsigned long flags, struct cr_img *pmi, u32 *id)
{
	return open_pages_image_at(get_service_fd(IMG_FD_OFF), flags, pmi, id);
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

off_t img_raw_size(struct cr_img *img)
{
	struct stat stat;

	if (fstat(img->_x.fd, &stat)) {
		pr_perror("Failed to get image stats");
		return -1;
	}

	return stat.st_size;
}
