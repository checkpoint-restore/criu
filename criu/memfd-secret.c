#include <sys/mman.h>
#include <stdbool.h>
#include <fcntl.h>
#include <unistd.h>

#include "memfd-secret.h"
#include "log.h"
#include "kerndat.h"
#include "files.h"
#include "protobuf.h"
#include "images/memfd-secret.pb-c.h"
#include "files-reg.h"
#include "imgset.h"
#include "util.h"
#include "namespaces.h"
#include "rst-malloc.h"
#include "fdstore.h"
#include "string.h"
#include "page.h"
#include "page-pipe.h"
#include "image-desc.h"
#include "page-xfer.h"
#include "stats.h"
#include "common/list.h"
#include "pagemap.h"
#include "mem.h"
#include "types.h"

#define PST_DIRTY 3

struct memfd_secret_dump_inode {
	struct list_head list;
	u32 id;
	u32 dev;
	u32 ino;
};

struct memfd_secret_restore_inode {
	struct list_head list;
	u32 id;
	mutex_t lock;
	int fdstore_id;
	MemfdSecretInodeEntry msie;
};

static LIST_HEAD(memfd_secret_inodes);

static u32 memfd_secret_inode_ids = 1;

/* secretmem dump */

struct secretmem_info {
	unsigned long secretmem_id;
	unsigned long size;
};

static int dump_pages(struct page_pipe *pp, struct page_xfer *xfer)
{
	struct page_pipe_buf *ppb;

	list_for_each_entry(ppb, &pp->bufs, l)
		if (vmsplice(ppb->p[1], ppb->iov, ppb->nr_segs, SPLICE_F_GIFT | SPLICE_F_NONBLOCK) !=
		    ppb->pages_in * PAGE_SIZE) {
			pr_perror("Can't get secretmem into page-pipe");
			return -1;
		}

	return page_xfer_dump_pages(xfer, pp);
}

static int do_dump_one_secretmem(void *addr, struct secretmem_info *smi)
{
	struct page_pipe *pp;
	struct page_xfer xfer;
	unsigned long nrpages, pfn;
	char buf[PAGE_SIZE];
	unsigned long pages[2] = {};
	int err, ret = -1;

	nrpages = (smi->size + PAGE_SIZE - 1) / PAGE_SIZE;

	pp = create_page_pipe((nrpages + 1) / 2, NULL, PP_CHUNK_MODE);
	if (!pp)
		goto err;

	err = open_page_xfer(&xfer, CR_FD_SECRETMEM_PAGEMAP, smi->secretmem_id);
	if (err)
		goto err_pp;

	xfer.offset = (unsigned long)addr;

	for (pfn = 0; pfn < nrpages; pfn++) {
		unsigned int pgstate = PST_DIRTY;
		unsigned long _pgaddr, pgaddr;
		int st = -1;

		_pgaddr = (unsigned long)addr + pfn * PAGE_SIZE;
		memset(buf, 0, PAGE_SIZE);
		/* secretmem areas can't be vmspliced */
		memcpy(buf, (void *)_pgaddr, smi->size);
		pgaddr = (unsigned long)buf;

		if (xfer.parent && page_in_parent(pgstate == PST_DIRTY)) {
			ret = page_pipe_add_hole(pp, pgaddr, PP_HOLE_PARENT);
			st = 0;
		} else {
			ret = page_pipe_add_page(pp, pgaddr, 0);
			st = 1;
		}

		if (ret)
			goto err_xfer;

		pages[st]++;
	}

	cnt_add(CNT_SECMEMPAGES_SCANNED, nrpages);
	cnt_add(CNT_SECMEMPAGES_SKIPPED_PARENT, pages[0]);
	cnt_add(CNT_SECMEMPAGES_WRITTEN, pages[1]);

	ret = dump_pages(pp, &xfer);

err_xfer:
	xfer.close(&xfer);
err_pp:
	destroy_page_pipe(pp);
err:
	return ret;
}

static int dump_one_memfd_secretmem(int fd, unsigned long secretmem_id, unsigned long size)
{
	int ret = -1;
	void *addr;
	struct secretmem_info smi;

	if (size == 0)
		return 0;

	memset(&smi, 0, sizeof(smi));
	smi.secretmem_id = secretmem_id;
	smi.size = size;

	addr = mmap(NULL, size, PROT_READ, MAP_SHARED, fd, 0);
	if (addr == MAP_FAILED) {
		pr_perror("Can't mmap secretmem 0x%lx", secretmem_id);
		return ret;
	}

	ret = do_dump_one_secretmem(addr, &smi);
	munmap(addr, size);

	return ret;
}

/* secretmem restore */

static int do_restore_secretmem_content(void *addr, unsigned long size, unsigned long secretmem_id)
{
	int ret = 0;
	struct page_read pr;

	ret = open_page_read(secretmem_id, &pr, PR_SECRETMEM);
	if (ret <= 0)
		return -1;

	while (1) {
		unsigned long vaddr;
		unsigned nr_pages;

		ret = pr.advance(&pr);
		if (ret <= 0)
			break;

		vaddr = (unsigned long)decode_pointer(pr.pe->vaddr);
		nr_pages = pr.pe->nr_pages;

		pr.read_pages(&pr, vaddr, nr_pages, addr, 0);
	}

	pr.close(&pr);
	return ret;
}

static int restore_secretmem_content(int fd, unsigned long secretmem_id, unsigned long size)
{
	void *addr = NULL;
	int ret = -1;

	if (size == 0)
		return 0;

	if (ftruncate(fd, size) < 0) {
		pr_perror("Can't resize secretmem 0x%lx size=%ld", secretmem_id, size);
		goto out;
	}

	addr = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (addr == MAP_FAILED) {
		pr_perror("Can't mmap secretmem 0x%lx size=%ld", secretmem_id, size);
		goto out;
	}

	if (do_restore_secretmem_content(addr, round_up(size, PAGE_SIZE), secretmem_id) < 0) {
		pr_perror("Can't restore secretmem content");
		goto out;
	}

	ret = 0;

out:
	if (addr)
		munmap(addr, size);
	return ret;
}

/* fd dump */

int is_memfd_secret(dev_t dev)
{
	/* struct kerndat_s */
	return dev == kdat.secretmem_dev;
}

static int dump_memfd_secret_inode(int fd, struct memfd_secret_dump_inode *inode, const struct stat *st)
{
	MemfdSecretInodeEntry msie = MEMFD_SECRET_INODE_ENTRY__INIT;
	int ret = -1;
	u32 secretmem_id;

	secretmem_id = inode->ino;

	pr_info("Dumping secretmem contents (id %#x, secretmem_id: %#x, size: %" PRIu64 ")\n", inode->id, secretmem_id,
		st->st_size);

	if (dump_one_memfd_secretmem(fd, secretmem_id, st->st_size) < 0)
		return ret;

	msie.inode_id = inode->id;
	msie.uid = userns_uid(st->st_uid);
	msie.gid = userns_gid(st->st_gid);
	msie.size = st->st_size;
	msie.secretmem_id = secretmem_id;

	if (pb_write_one(img_from_set(glob_imgset, CR_FD_MEMFD_SECRET_INODE), &msie, PB_MEMFD_SECRET_INODE))
		return ret;

	return 0;
}

static struct memfd_secret_dump_inode *dump_unique_memfd_secret_inode(int lfd, const struct stat *st)
{
	struct memfd_secret_dump_inode *inode;

	list_for_each_entry(inode, &memfd_secret_inodes, list)
		if ((inode->dev == st->st_dev) && (inode->ino == st->st_ino))
			return inode;

	inode = xmalloc(sizeof(*inode));
	if (inode == NULL)
		return NULL;

	inode->dev = st->st_dev;
	inode->ino = st->st_ino;
	inode->id = memfd_secret_inode_ids++;

	if (dump_memfd_secret_inode(lfd, inode, st)) {
		xfree(inode);
		return NULL;
	}

	list_add_tail(&inode->list, &memfd_secret_inodes);

	return inode;
}

static int dump_one_memfd_secret(int lfd, u32 id, const struct fd_parms *p)
{
	MemfdSecretFileEntry msfe = MEMFD_SECRET_FILE_ENTRY__INIT;
	FileEntry fe = FILE_ENTRY__INIT;
	struct memfd_secret_dump_inode *inode;
	struct fd_link _link, *link;

	if (!p->link) {
		if (fill_fdlink(lfd, p, &_link))
			return -1;
		link = &_link;
	} else
		link = p->link;

	link_strip_deleted(link); /* link->name: ./secretmem */

	inode = dump_unique_memfd_secret_inode(lfd, &p->stat);
	if (!inode)
		return -1;

	msfe.id = id;
	msfe.flags = p->flags;
	msfe.pos = p->pos;
	msfe.fown = (FownEntry *)&p->fown;
	msfe.inode_id = inode->id;

	fe.type = FD_TYPES__MEMFD_SECRET;
	fe.id = msfe.id;
	fe.memfd_secret = &msfe;

	return pb_write_one(img_from_set(glob_imgset, CR_FD_FILES), &fe, PB_FILE);
}

const struct fdtype_ops memfd_secret_dump_ops = {
	.type = FD_TYPES__MEMFD_SECRET,
	.dump = dump_one_memfd_secret,
};

/* fd restore */

struct memfd_secret_info {
	MemfdSecretFileEntry *msfe;
	struct file_desc d;
	struct memfd_secret_restore_inode *inode;
};

static struct memfd_secret_restore_inode *memfd_secret_alloc_inode(int id)
{
	struct memfd_secret_restore_inode *inode;

	list_for_each_entry(inode, &memfd_secret_inodes, list)
		if (inode->id == id)
			return inode;

	inode = shmalloc(sizeof(*inode));
	if (!inode)
		return NULL;

	inode->id = id;
	mutex_init(&inode->lock);
	inode->fdstore_id = -1;

	list_add_tail(&inode->list, &memfd_secret_inodes);
	return inode;
}

static int memfd_secret_open_inode_nocache(struct memfd_secret_restore_inode *inode)
{
	MemfdSecretInodeEntry *msie = NULL;
	struct cr_img *img = NULL;
	int fd = -1;
	int ret = -1;
	int flags = 0;

	img = open_image(CR_FD_MEMFD_SECRET_INODE, O_RSTR, inode->id);
	if (!img)
		goto out_free;

	if (pb_read_one(img, &msie, PB_MEMFD_SECRET_INODE) < 0)
		goto out_free;

	fd = memfd_secret(flags);
	if (fd < 0) {
		pr_perror("Can't create memfd_secret");
		goto out_free;
	}

	if (restore_secretmem_content(fd, msie->secretmem_id, msie->size))
		goto out_free;

	if (cr_fchown(fd, msie->uid, msie->gid)) {
		pr_perror("Can't change uid %d gid %d of memfd-secret", (int)msie->uid, (int)msie->gid);
		goto out_free;
	}

	inode->fdstore_id = fdstore_add(fd);
	if (inode->fdstore_id < 0)
		goto out_free;

	ret = fd;
	fd = -1;

out_free:
	if (img)
		close_image(img);
	if (fd != -1)
		close(fd);
	if (msie)
		memfd_secret_inode_entry__free_unpacked(msie, NULL);

	return ret;
}

static int memfd_secret_open_inode(struct memfd_secret_restore_inode *inode)
{
	int fd;

	mutex_lock(&inode->lock);
	if (inode->fdstore_id != -1)
		fd = fdstore_get(inode->fdstore_id);
	else
		fd = memfd_secret_open_inode_nocache(inode);
	mutex_unlock(&inode->lock);

	return fd;
}

static int memfd_secret_open(struct file_desc *d, u32 *fdflags)
{
	struct memfd_secret_info *msfi;
	MemfdSecretFileEntry *msfe;
	int fd;

	msfi = container_of(d, struct memfd_secret_info, d);
	msfe = msfi->msfe;

	if (inherited_fd(d, &fd))
		return fd;

	pr_info("Restoring memfd_secret id=%d\n", msfe->id);

	fd = memfd_secret_open_inode(msfi->inode);
	if (fd < 0)
		return -1;

	return fd;
}

static int memfd_secret_open_fe_fd(struct file_desc *fd, int *new_fd)
{
	int tmp;

	tmp = memfd_secret_open(fd, NULL);
	if (tmp < 0)
		return -1;

	*new_fd = tmp;
	return 0;
}

static struct file_desc_ops memfd_secret_desc_ops = {
	.type = FD_TYPES__MEMFD_SECRET,
	.open = memfd_secret_open_fe_fd,
};

static int collect_one_memfd_secret(void *o, ProtobufCMessage *msg, struct cr_img *i)
{
	struct memfd_secret_info *info = o;

	info->msfe = pb_msg(msg, MemfdSecretFileEntry);
	info->inode = memfd_secret_alloc_inode(info->msfe->inode_id);
	if (!info->inode)
		return -1;

	return file_desc_add(&info->d, info->msfe->id, &memfd_secret_desc_ops);
}

struct collect_image_info memfd_secret_cinfo = {
	.fd_type = CR_FD_MEMFD_SECRET_FILE,
	.pb_type = PB_MEMFD_SECRET_FILE,
	.priv_size = sizeof(struct memfd_secret_info),
	.collect = collect_one_memfd_secret,
};
