#include <unistd.h>
#include <sys/mman.h>
#include <stdlib.h>
#include <fcntl.h>

#include "pid.h"
#include "shmem.h"
#include "image.h"
#include "cr_options.h"
#include "kerndat.h"
#include "page-pipe.h"
#include "page-xfer.h"
#include "rst-malloc.h"
#include "vma.h"
#include "config.h"
#include "syscall-codes.h"

#include "protobuf.h"
#include "images/pagemap.pb-c.h"

/*
 * pid is a pid of a creater
 * start, end are used for open mapping
 * fd is a file discriptor, which is valid for creater,
 * it's opened in cr-restor, because pgoff may be non zero
 */
struct shmem_info {
	unsigned long	shmid;
	unsigned long	size;
	int		pid;
	int		fd;

	/*
	 * 0. lock is initilized to zero
	 * 1. the master opens a descriptor and set lock to 1
	 * 2. slaves open their descriptors and increment lock
	 * 3. the master waits all slaves on lock. After that
	 *    it can close the descriptor.
	 */
	futex_t		lock;

	/*
	 * Here is a problem, that we don't know, which process will restore
	 * an region. Each time when we	found a process with a smaller pid,
	 * we reset self_count, so we can't have only one counter.
	 */
	int		count;		/* the number of regions */
	int		self_count;	/* the number of regions, which belongs to "pid" */

	struct list_head l;
};

/*
 * This list is filled with shared objects before we fork
 * any tasks. Thus the head is private (COW-ed) and the
 * entries are all in shmem.
 */
static LIST_HEAD(shmems); /* XXX hash? tree? */

void show_saved_shmems(void)
{
	struct shmem_info *si;

	pr_info("\tSaved shmems:\n");
	list_for_each_entry(si, &shmems, l)
		pr_info("\t\tshmid: 0x%lx pid: %d\n", si->shmid, si->pid);
}

static struct shmem_info *find_shmem_by_id(unsigned long shmid)
{
	struct shmem_info *si;

	list_for_each_entry(si, &shmems, l)
		if (si->shmid == shmid)
			return si;

	return NULL;
}

int collect_shmem(int pid, VmaEntry *vi)
{
	unsigned long size = vi->pgoff + vi->end - vi->start;
	struct shmem_info *si;

	si = find_shmem_by_id(vi->shmid);
	if (si) {

		if (si->size < size)
			si->size = size;
		si->count++;

		/*
		 * Only the shared mapping with a lowest
		 * pid will be created in real, other processes
		 * will wait until the kernel propagate this mapping
		 * into /proc
		 */
		if (!pid_rst_prio(pid, si->pid)) {
			if (si->pid == pid)
				si->self_count++;

			return 0;
		}

		si->pid	 = pid;
		si->self_count = 1;

		return 0;
	}

	si = shmalloc(sizeof(struct shmem_info));
	if (!si)
		return -1;

	pr_info("Add new shmem 0x%"PRIx64" (0x%016"PRIx64"-0x%016"PRIx64")\n",
				vi->shmid, vi->start, vi->end);

	si->shmid = vi->shmid;
	si->pid	  = pid;
	si->size  = size;
	si->fd    = -1;
	si->count = 1;
	si->self_count = 1;
	futex_init(&si->lock);
	list_add_tail(&si->l, &shmems);

	return 0;
}

static int shmem_wait_and_open(int pid, struct shmem_info *si)
{
	char path[128];
	int ret;

	pr_info("Waiting for the %lx shmem to appear\n", si->shmid);
	futex_wait_while(&si->lock, 0);

	snprintf(path, sizeof(path), "/proc/%d/fd/%d",
		si->pid, si->fd);

	pr_info("Opening shmem [%s] \n", path);
	ret = open_proc_rw(si->pid, "fd/%d", si->fd);
	if (ret < 0)
		pr_perror("     %d: Can't stat shmem at %s",
				si->pid, path);
	futex_inc_and_wake(&si->lock);
	return ret;
}

static int restore_shmem_content(void *addr, struct shmem_info *si)
{
	int ret = 0, fd_pg;
	struct page_read pr;
	unsigned long off_real;

	ret = open_page_read(si->shmid, &pr, PR_SHMEM);
	if (ret <= 0)
		return -1;

	fd_pg = img_raw_fd(pr.pi);
	while (1) {
		unsigned long vaddr;
		unsigned nr_pages;
		struct iovec iov;

		ret = pr.get_pagemap(&pr, &iov);
		if (ret <= 0)
			break;

		vaddr = (unsigned long)iov.iov_base;
		nr_pages = iov.iov_len / PAGE_SIZE;

		if (vaddr + nr_pages * PAGE_SIZE > si->size)
			break;

		off_real = lseek(fd_pg, 0, SEEK_CUR);

		ret = read(fd_pg, addr + vaddr, nr_pages * PAGE_SIZE);
		if (ret != nr_pages * PAGE_SIZE) {
			ret = -1;
			break;
		}

		if (opts.auto_dedup) {
			ret = punch_hole(&pr, off_real, nr_pages * PAGE_SIZE, false);
			if (ret == -1) {
				break;
			}
		}

		if (pr.put_pagemap)
			pr.put_pagemap(&pr);
	}

	pr.close(&pr);
	return ret;
}

int get_shmem_fd(int pid, VmaEntry *vi)
{
	struct shmem_info *si;
	void *addr = MAP_FAILED;
	int f = -1;
	int flags;

	si = find_shmem_by_id(vi->shmid);
	pr_info("Search for 0x%016"PRIx64" shmem 0x%"PRIx64" %p/%d\n", vi->start, vi->shmid, si, si ? si->pid : -1);
	if (!si) {
		pr_err("Can't find my shmem 0x%016"PRIx64"\n", vi->start);
		return -1;
	}

	if (si->pid != pid)
		return shmem_wait_and_open(pid, si);

	if (si->fd != -1)
		return dup(si->fd);

	flags = MAP_SHARED;
#ifdef CONFIG_HAS_MEMFD
	if (kdat.has_memfd) {
		f = syscall(SYS_memfd_create, "", 0);
		if (f < 0) {
			pr_perror("Unable to create memfd");
			goto err;
		}

		if (ftruncate(f, si->size)) {
			pr_perror("Unable to truncate memfd");
			goto err;
		}
		flags |= MAP_FILE;
	} else
#endif
		flags |= MAP_ANONYMOUS;

	/*
	 * The following hack solves problems:
	 * vi->pgoff may be not zero in a target process.
	 * This mapping may be mapped more then once.
	 * The restorer doesn't have snprintf.
	 * Here is a good place to restore content
	 */
	addr = mmap(NULL, si->size, PROT_WRITE | PROT_READ, flags, f, 0);
	if (addr == MAP_FAILED) {
		pr_err("Can't mmap shmid=0x%"PRIx64" size=%ld\n",
				vi->shmid, si->size);
		goto err;
	}

	if (restore_shmem_content(addr, si) < 0) {
		pr_err("Can't restore shmem content\n");
		goto err;
	}

	if (f == -1) {
		f = open_proc_rw(getpid(), "map_files/%lx-%lx",
				(unsigned long) addr,
				(unsigned long) addr + si->size);
		if (f < 0)
			goto err;
	}
	munmap(addr, si->size);

	si->fd = f;

	/* Send signal to slaves, that they can open fd for this shmem */
	futex_inc_and_wake(&si->lock);
	/*
	 * All other regions in this process will duplicate
	 * the file descriptor, so we don't wait them.
	 */
	futex_wait_until(&si->lock, si->count - si->self_count + 1);

	return f;
err:
	if (addr != MAP_FAILED)
		munmap(addr, si->size);
	close_safe(&f);
	return -1;
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

static int dump_pages(struct page_pipe *pp, struct page_xfer *xfer, void *addr)
{
	struct page_pipe_buf *ppb;

	list_for_each_entry(ppb, &pp->bufs, l)
		if (vmsplice(ppb->p[1], ppb->iov, ppb->nr_segs,
					SPLICE_F_GIFT | SPLICE_F_NONBLOCK) !=
				ppb->pages_in * PAGE_SIZE) {
			pr_perror("Can't get shmem into page-pipe");
			return -1;
		}

	return page_xfer_dump_pages(xfer, pp, (unsigned long)addr);
}

static int dump_one_shmem(struct shmem_info_dump *si)
{
	struct iovec *iovs;
	struct page_pipe *pp;
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

	pp = create_page_pipe((nrpages + 1) / 2, iovs, true);
	if (!pp)
		goto err_iovs;

	err = open_page_xfer(&xfer, CR_FD_SHMEM_PAGEMAP, si->shmid);
	if (err)
		goto err_pp;

	for (pfn = 0; pfn < nrpages; pfn++) {
		if (!(map[pfn] & PAGE_RSS))
			continue;
again:
		ret = page_pipe_add_page(pp, (unsigned long)addr + pfn * PAGE_SIZE);
		if (ret == -EAGAIN) {
			ret = dump_pages(pp, &xfer, addr);
			if (ret)
				goto err_xfer;
			page_pipe_reinit(pp);
			goto again;
		} else if (ret)
			goto err_xfer;
	}

	ret = dump_pages(pp, &xfer, addr);

err_xfer:
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
