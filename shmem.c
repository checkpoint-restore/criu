#include <unistd.h>
#include <sys/mman.h>
#include <stdlib.h>

#include "shmem.h"
#include "image.h"
#include "crtools.h"
#include "restorer.h"
#include "page-pipe.h"
#include "page-xfer.h"
#include "protobuf.h"
#include "protobuf/pagemap.pb-c.h"

struct shmems *rst_shmems;

void show_saved_shmems(void)
{
	int i;

	pr_info("\tSaved shmems:\n");

	for (i = 0; i < rst_shmems->nr_shmems; i++)
		pr_info("\t\tstart: 0x%016lx shmid: 0x%lx pid: %d\n",
			rst_shmems->entries[i].start,
			rst_shmems->entries[i].shmid,
			rst_shmems->entries[i].pid);
}

static int collect_shmem(int pid, VmaEntry *vi)
{
	int nr_shmems = rst_shmems->nr_shmems;
	unsigned long size = vi->pgoff + vi->end - vi->start;
	struct shmem_info *si;

	si = find_shmem(rst_shmems, vi->shmid);
	if (si) {

		if (si->size < size)
			si->size = size;

		/*
		 * Only the shared mapping with a lowest
		 * pid will be created in real, other processes
		 * will wait until the kernel propagate this mapping
		 * into /proc
		 */
		if (si->pid <= pid)
			return 0;

		si->pid	 = pid;
		si->start = vi->start;
		si->end	 = vi->end;

		return 0;
	}

	if ((nr_shmems + 1) * sizeof(struct shmem_info) +
					sizeof (struct shmems) >= SHMEMS_SIZE) {
		pr_err("OOM storing shmems\n");
		return -1;
	}

	pr_info("Add new shmem 0x%"PRIx64" (0x0160x%"PRIx64"-0x0160x%"PRIx64")\n",
				vi->shmid, vi->start, vi->end);

	si = &rst_shmems->entries[nr_shmems];
	rst_shmems->nr_shmems++;

	si->start = vi->start;
	si->end	  = vi->end;
	si->shmid = vi->shmid;
	si->pid	  = pid;
	si->size  = size;
	si->fd    = -1;

	futex_init(&si->lock);

	return 0;
}

int prepare_shmem_pid(int pid)
{
	int fd, ret = -1;
	VmaEntry *vi;

	fd = open_image(CR_FD_VMAS, O_RSTR, pid);
	if (fd < 0) {
		if (errno == ENOENT)
			return 0;
		else
			return -1;
	}

	while (1) {
		ret = pb_read_one_eof(fd, &vi, PB_VMAS);
		if (ret <= 0)
			break;

		pr_info("vma 0x%"PRIx64" 0x%"PRIx64"\n", vi->start, vi->end);

		if (!vma_entry_is(vi, VMA_ANON_SHARED) ||
		    vma_entry_is(vi, VMA_AREA_SYSVIPC)) {
			vma_entry__free_unpacked(vi, NULL);
			continue;
		}

		ret = collect_shmem(pid, vi);
		vma_entry__free_unpacked(vi, NULL);

		if (ret)
			break;
	}

	close(fd);
	return ret;
}

static int shmem_wait_and_open(int pid, struct shmem_info *si)
{
	char path[128];
	int ret;

	snprintf(path, sizeof(path), "/proc/%d/map_files/%lx-%lx",
		si->pid, si->start, si->end);

	pr_info("Waiting for [%s] to appear\n", path);
	futex_wait_until(&si->lock, 1);

	pr_info("Opening shmem [%s] \n", path);
	ret = open_proc_rw(si->pid, "map_files/%lx-%lx", si->start, si->end);
	if (ret < 0)
		pr_perror("     %d: Can't stat shmem at %s",
				si->pid, path);
	return ret;
}

static int restore_shmem_content(void *addr, struct shmem_info *si)
{
	int fd, fd_pg, ret = 0;

	fd = open_image(CR_FD_SHMEM_PAGEMAP, O_RSTR, si->shmid);
	if (fd < 0) {
		fd_pg = open_image(CR_FD_SHM_PAGES_OLD, O_RSTR, si->shmid);
		if (fd_pg < 0)
			goto err_unmap;
	} else {
		fd_pg = open_pages_image(O_RSTR, fd);
		if (fd_pg < 0)
			goto out_close;
	}

	while (1) {
		unsigned long vaddr;
		unsigned nr_pages;

		if (fd >= 0) {
			PagemapEntry *pe;

			ret = pb_read_one_eof(fd, &pe, PB_PAGEMAP);
			if (ret <= 0)
				break;

			vaddr = (unsigned long)decode_pointer(pe->vaddr);
			nr_pages = pe->nr_pages;

			pagemap_entry__free_unpacked(pe, NULL);
		} else {
			__u64 img_vaddr;

			ret = read_img_eof(fd_pg, &img_vaddr);
			if (ret <= 0)
				break;

			vaddr = (unsigned long)decode_pointer(img_vaddr);
			nr_pages = 1;
		}

		if (vaddr + nr_pages * PAGE_SIZE > si->size)
			break;

		ret = read(fd_pg, addr + vaddr, nr_pages * PAGE_SIZE);
		if (ret != nr_pages * PAGE_SIZE) {
			ret = -1;
			break;
		}

	}

	close_safe(&fd_pg);
	close_safe(&fd);
	return ret;

out_close:
	close_safe(&fd);
err_unmap:
	munmap(addr,  si->size);
	return -1;
}

int get_shmem_fd(int pid, VmaEntry *vi)
{
	struct shmem_info *si;
	void *addr;
	int f;

	si = find_shmem(rst_shmems, vi->shmid);
	pr_info("Search for 0x%016"PRIx64" shmem 0x%"PRIx64" %p/%d\n", vi->start, vi->shmid, si, si ? si->pid : -1);
	if (!si) {
		pr_err("Can't find my shmem 0x%016"PRIx64"\n", vi->start);
		return -1;
	}

	if (si->pid != pid)
		return shmem_wait_and_open(pid, si);

	if (si->fd != -1)
		return dup(si->fd);

	/*
	 * The following hack solves problems:
	 * vi->pgoff may be not zero in a target process.
	 * This mapping may be mapped more then once.
	 * The restorer doesn't have snprintf.
	 * Here is a good place to restore content
	 */
	addr = mmap(NULL, si->size,
			PROT_WRITE | PROT_READ,
			MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (addr == MAP_FAILED) {
		pr_err("Can't mmap shmid=0x%"PRIx64" size=%ld\n",
				vi->shmid, si->size);
		return -1;
	}

	if (restore_shmem_content(addr, si) < 0) {
		pr_err("Can't restore shmem content\n");
		return -1;
	}

	f = open_proc_rw(getpid(), "map_files/%lx-%lx",
			(unsigned long) addr,
			(unsigned long) addr + si->size);
	munmap(addr, si->size);
	if (f < 0)
		return -1;

	si->fd = f;
	return f;
}

int prepare_shmem_restore(void)
{
	rst_shmems = mmap(NULL, SHMEMS_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANON, 0, 0);
	if (rst_shmems == MAP_FAILED) {
		pr_perror("Can't map shmem");
		return -1;
	}

	rst_shmems->nr_shmems = 0;
	return 0;
}

struct shmem_info_dump {
	unsigned long	size;
	unsigned long	shmid;
	unsigned long	start;
	unsigned long	end;
	int		pid;

	struct shmem_info_dump *next;
};

#define SHMEM_HASH_SIZE	32
static struct shmem_info_dump *shmems_hash[SHMEM_HASH_SIZE];

static struct shmem_info_dump *shmem_find(struct shmem_info_dump **chain,
		unsigned long shmid)
{
	struct shmem_info_dump *sh;

	for (sh = *chain; sh; sh = sh->next)
		if (sh->shmid == shmid)
			return sh;

	return NULL;
}

int add_shmem_area(pid_t pid, VmaEntry *vma)
{
	struct shmem_info_dump *si, **chain;
	unsigned long size = vma->pgoff + (vma->end - vma->start);

	chain = &shmems_hash[vma->shmid % SHMEM_HASH_SIZE];
	si = shmem_find(chain, vma->shmid);
	if (si) {
		if (si->size < size)
			si->size = size;
		return 0;
	}

	si = xmalloc(sizeof(*si));
	if (!si)
		return -1;

	si->next = *chain;
	*chain = si;

	si->size = size;
	si->pid = pid;
	si->start = vma->start;
	si->end = vma->end;
	si->shmid = vma->shmid;

	return 0;
}

static int dump_one_shmem(struct shmem_info_dump *si)
{
	struct iovec *iovs;
	struct page_pipe *pp;
	struct page_pipe_buf *ppb;
	struct page_xfer xfer;
	int err, ret = -1, fd;
	unsigned char *map = NULL;
	void *addr = NULL;
	unsigned long pfn, nrpages;

	pr_info("Dumping shared memory %ld\n", si->shmid);

	nrpages = (si->size + PAGE_SIZE - 1) / PAGE_SIZE;
	map = xmalloc(nrpages * sizeof(*map));
	if (!map)
		goto err;

	fd = open_proc(si->pid, "map_files/%lx-%lx", si->start, si->end);
	if (fd < 0)
		goto err;

	addr = mmap(NULL, si->size, PROT_READ, MAP_SHARED, fd, 0);
	close(fd);
	if (addr == MAP_FAILED) {
		pr_err("Can't map shmem 0x%lx (0x%lx-0x%lx)\n",
				si->shmid, si->start, si->end);
		goto err;
	}

	/*
	 * We can't use pagemap here, because this vma is
	 * not mapped to us at all, but mincore reports the
	 * pagecache status of a file, which is correct in
	 * this case.
	 */

	err = mincore(addr, si->size, map);
	if (err)
		goto err_unmap;

	iovs = xmalloc(((nrpages + 1) / 2) * sizeof(struct iovec));
	if (!iovs)
		goto err_unmap;

	pp = create_page_pipe((nrpages + 1) / 2, iovs);
	if (!pp)
		goto err_iovs;

	for (pfn = 0; pfn < nrpages; pfn++) {
		if (!(map[pfn] & PAGE_RSS))
			continue;

		if (page_pipe_add_page(pp, (unsigned long)addr + pfn * PAGE_SIZE))
			goto err_pp;
	}

	list_for_each_entry(ppb, &pp->bufs, l)
		if (vmsplice(ppb->p[1], ppb->iov, ppb->nr_segs,
					SPLICE_F_GIFT | SPLICE_F_NONBLOCK) !=
				ppb->pages_in * PAGE_SIZE) {
			pr_perror("Can't get shmem into page-pipe");
			goto err_pp;
		}

	err = open_page_xfer(&xfer, CR_FD_SHMEM_PAGEMAP, si->shmid);
	if (err)
		goto err_pp;

	ret = page_xfer_dump_pages(&xfer, pp, (unsigned long)addr);

	xfer.close(&xfer);
err_pp:
	destroy_page_pipe(pp);
err_iovs:
	xfree(iovs);
err_unmap:
	munmap(addr,  si->size);
err:
	xfree(map);
	return ret;
}

#define for_each_shmem_dump(_i, _si)				\
	for (i = 0; i < SHMEM_HASH_SIZE; i++)			\
		for (si = shmems_hash[i]; si; si = si->next)

int cr_dump_shmem(void)
{
	int ret = 0, i;
	struct shmem_info_dump *si;

	for_each_shmem_dump (i, si) {
		ret = dump_one_shmem(si);
		if (ret)
			break;
	}

	return ret;
}
