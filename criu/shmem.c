#include <unistd.h>
#include <sys/mman.h>
#include <stdlib.h>
#include <fcntl.h>
#include <stdbool.h>

#include "common/config.h"
#include "common/list.h"
#include "pid.h"
#include "shmem.h"
#include "image.h"
#include "cr_options.h"
#include "kerndat.h"
#include "page-pipe.h"
#include "page-xfer.h"
#include "rst-malloc.h"
#include "vma.h"
#include "mem.h"
#include <compel/plugins/std/syscall-codes.h>
#include "bitops.h"
#include "log.h"
#include "types.h"
#include "page.h"
#include "util.h"
#include "protobuf.h"
#include "images/pagemap.pb-c.h"

#ifndef SEEK_DATA
#define SEEK_DATA	3
#define SEEK_HOLE	4
#endif

/*
 * Hash table and routines for keeping shmid -> shmem_xinfo mappings
 */

/*
 * The hash is filled with shared objects before we fork
 * any tasks. Thus the heads are private (COW-ed) and the
 * entries are all in shmem.
 */
#define SHMEM_HASH_SIZE	32
static struct hlist_head shmems_hash[SHMEM_HASH_SIZE];

#define for_each_shmem(_i, _si)				\
	for (i = 0; i < SHMEM_HASH_SIZE; i++)			\
		hlist_for_each_entry(_si, &shmems_hash[_i], h)

struct shmem_info {
	struct hlist_node h;
	unsigned long	shmid;

	/*
	 * Owner PID. This guy creates anon shmem on restore and
	 * from this the shmem is read on dump
	 */
	int		pid;
	unsigned long	size;

	union {
		struct { /* For restore */
			/*
			 * Descriptor by which this shmem is opened
			 * by the creator
			 */
			int		fd;

			/*
			 * 0. lock is initialized to zero
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
		};

		struct { /* For sysvipc restore */
			struct list_head att; /* list of shmem_sysv_att-s */
			int		 want_write;
		};

		struct { /* For dump */
			unsigned long	start;
			unsigned long	end;
			unsigned long	*pstate_map;
		};
	};
};

struct shmem_sysv_att {
	struct list_head l;
	VmaEntry	*first;
	unsigned long	prev_end;
};

/* This is the "pid that will restore shmem" value for sysv */
#define SYSVIPC_SHMEM_PID	(-1)

static inline struct hlist_head *shmem_chain(unsigned long shmid)
{
	return &shmems_hash[shmid % SHMEM_HASH_SIZE];
}

static void shmem_hash_add(struct shmem_info *si)
{
	struct hlist_head *chain;

	chain = shmem_chain(si->shmid);
	hlist_add_head(&si->h, chain);
}

static struct shmem_info *shmem_find(unsigned long shmid)
{
	struct hlist_head *chain;
	struct shmem_info *si;

	chain = shmem_chain(shmid);
	hlist_for_each_entry(si, chain, h)
		if (si->shmid == shmid)
			return si;

	return NULL;
}

#define PST_DONT_DUMP 0
#define PST_DUMP 1
#define PST_ZERO 2
#define PST_DIRTY 3

#define PST_BITS 2
#define PST_BIT0_IX(pfn) ((pfn) * PST_BITS)
#define PST_BIT1_IX(pfn) (PST_BIT0_IX(pfn) + 1)

/*
 * Disable pagemap based shmem changes tracking by default
 * because it has bugs in implementation -
 * process can map shmem page, change it and unmap it.
 * We won't observe any changes in such pagemaps during dump.
 */
static bool is_shmem_tracking_en(void)
{
	static bool is_inited = false;
	static bool is_enabled = false;

	if (!is_inited) {
		is_enabled = (bool)getenv("CRIU_TRACK_SHMEM");
		is_inited = true;
		if (is_enabled)
			pr_msg("Turn anon shmem tracking on via env\n");
	}
	return is_enabled;
}

static unsigned int get_pstate(unsigned long *pstate_map, unsigned long pfn)
{
	unsigned int bit0 = test_bit(PST_BIT0_IX(pfn), pstate_map) ? 1 : 0;
	unsigned int bit1 = test_bit(PST_BIT1_IX(pfn), pstate_map) ? 1 : 0;
	return (bit1 << 1) | bit0;
}

static void set_pstate(unsigned long *pstate_map, unsigned long pfn,
		unsigned int pstate)
{
	if (pstate & 1)
		set_bit(PST_BIT0_IX(pfn), pstate_map);
	if (pstate & 2)
		set_bit(PST_BIT1_IX(pfn), pstate_map);
}

static int expand_shmem(struct shmem_info *si, unsigned long new_size)
{
	unsigned long nr_pages, nr_map_items, map_size,
				nr_new_map_items, new_map_size, old_size;

	old_size = si->size;
	si->size = new_size;
	if (!is_shmem_tracking_en())
		return 0;

	nr_pages = DIV_ROUND_UP(old_size, PAGE_SIZE);
	nr_map_items = BITS_TO_LONGS(nr_pages * PST_BITS);
	map_size = nr_map_items * sizeof(*si->pstate_map);

	nr_pages = DIV_ROUND_UP(new_size, PAGE_SIZE);
	nr_new_map_items = BITS_TO_LONGS(nr_pages * PST_BITS);
	new_map_size = nr_new_map_items * sizeof(*si->pstate_map);

	BUG_ON(new_map_size < map_size);

	si->pstate_map = xrealloc(si->pstate_map, new_map_size);
	if (!si->pstate_map)
		return -1;
	memzero(si->pstate_map + nr_map_items, new_map_size - map_size);
	return 0;
}

static void update_shmem_pmaps(struct shmem_info *si, u64 *map, VmaEntry *vma)
{
	unsigned long shmem_pfn, vma_pfn, vma_pgcnt;

	if (!is_shmem_tracking_en())
		return;

	vma_pgcnt = DIV_ROUND_UP(si->size - vma->pgoff, PAGE_SIZE);
	for (vma_pfn = 0; vma_pfn < vma_pgcnt; ++vma_pfn) {
		if (!should_dump_page(vma, map[vma_pfn]))
			continue;

		shmem_pfn = vma_pfn + DIV_ROUND_UP(vma->pgoff, PAGE_SIZE);
		if (map[vma_pfn] & PME_SOFT_DIRTY)
			set_pstate(si->pstate_map, shmem_pfn, PST_DIRTY);
		else if (page_is_zero(map[vma_pfn]))
			set_pstate(si->pstate_map, shmem_pfn, PST_ZERO);
		else
			set_pstate(si->pstate_map, shmem_pfn, PST_DUMP);
	}
}

int collect_sysv_shmem(unsigned long shmid, unsigned long size)
{
	struct shmem_info *si;

	/*
	 * Tasks will not modify this object, so don't
	 * shmalloc() as we do it for anon shared mem
	 */
	si = malloc(sizeof(*si));
	if (!si)
		return -1;

	si->shmid = shmid;
	si->pid = SYSVIPC_SHMEM_PID;
	si->size = size;
	si->want_write = 0;
	INIT_LIST_HEAD(&si->att);

	shmem_hash_add(si);

	pr_info("Collected SysV shmem %lx, size %ld\n", si->shmid, si->size);

	return 0;
}

int fixup_sysv_shmems(void)
{
	int i;
	struct shmem_info *si;
	struct shmem_sysv_att *att;

	for_each_shmem(i, si) {
		/* It can be anon shmem */
		if (si->pid != SYSVIPC_SHMEM_PID)
			continue;

		list_for_each_entry(att, &si->att, l) {
			/*
			 * Same thing is checked in open_shmem_sysv() for
			 * intermediate holes.
			 */
			if (att->first->start + round_up(si->size, page_size()) != att->prev_end) {
				pr_err("Sysv shmem %lx with tail hole not supported\n", si->shmid);
				return -1;
			}

			/*
			 * See comment in open_shmem_sysv() about this PROT_EXEC
			 */
			if (si->want_write)
				att->first->prot |= PROT_EXEC;
		}
	}

	return 0;
}

static int open_shmem_sysv(int pid, struct vma_area *vma)
{
	VmaEntry *vme = vma->e;
	struct shmem_info *si;
	struct shmem_sysv_att *att;
	uint64_t ret_fd;

	si = shmem_find(vme->shmid);
	if (!si) {
		pr_err("Can't find sysv shmem for %"PRIx64"\n", vme->shmid);
		return -1;
	}

	if (si->pid != SYSVIPC_SHMEM_PID) {
		pr_err("SysV shmem vma 0x%"PRIx64" points to anon vma %lx\n",
				vme->start, si->shmid);
		return -1;
	}

	/*
	 * We can have a chain of VMAs belonging to the same
	 * sysv shmem segment all with different access rights
	 * (ro and rw). But single shmat() system call attaches
	 * the whole segment regardless of the actual mapping
	 * size. This can be achieved by attaching a segment
	 * and then write-protecting its parts.
	 *
	 * So, to restore this thing we note the very first
	 * area of the segment and make it restore the whole
	 * thing. All the subsequent ones will carry the sign
	 * telling the restorer to omit shmat and only do the
	 * ro protection. Yes, it may happen that some sysv
	 * shmem vma-s sit in the list (and restorer's array)
	 * for no use.
	 *
	 * Holes in between are not handled now, as well as
	 * the hole at the end (see fixup_sysv_shmems).
	 *
	 * One corner case. At shmat() time we need to know
	 * whether to create the segment rw or ro, but the
	 * first vma can have different protection. So the
	 * segment ro-ness is marked with PROT_EXEC bit in
	 * the first vma. Unfortunately, we only know this
	 * after we scan all the vmas, so this bit is set
	 * at the end in fixup_sysv_shmems().
	 */

	if (vme->pgoff == 0) {
		att = xmalloc(sizeof(*att));
		if (!att)
			return -1;

		att->first = vme;
		list_add(&att->l, &si->att);

		ret_fd = si->shmid;
	} else {
		att = list_first_entry(&si->att, struct shmem_sysv_att, l);
		if (att->prev_end != vme->start) {
			pr_err("Sysv shmem %lx with a hole not supported\n", si->shmid);
			return -1;
		}
		if (vme->pgoff != att->prev_end - att->first->start) {
			pr_err("Sysv shmem %lx with misordered attach chunks\n", si->shmid);
			return -1;
		}

		/*
		 * Value that doesn't (shouldn't) match with any real
		 * sysv shmem ID (thus it cannot be 0, as shmem id can)
		 * and still is not negative to prevent prepare_vmas() from
		 * treating it as error.
		 */
		ret_fd = SYSV_SHMEM_SKIP_FD;
	}

	pr_info("Note 0x%"PRIx64"-0x%"PRIx64" as %lx sysvshmem\n", vme->start, vme->end, si->shmid);

	att->prev_end = vme->end;
	if (!vme->has_fdflags || vme->fdflags == O_RDWR)
		/*
		 * We can't look at vma->prot & PROT_WRITE as all this stuff
		 * can be read-protected. If !has_fdflags these are old images
		 * and ... we have no other choice other than make it with
		 * maximum access :(
		 */
		si->want_write = 1;

	vme->fd = ret_fd;
	return 0;
}

static int open_shmem(int pid, struct vma_area *vma);

int collect_shmem(int pid, struct vma_area *vma)
{
	VmaEntry *vi = vma->e;
	unsigned long size = vi->pgoff + vi->end - vi->start;
	struct shmem_info *si;

	if (vma_entry_is(vi, VMA_AREA_SYSVIPC)) {
		vma->vm_open = open_shmem_sysv;
		return 0;
	}

	vma->vm_open = open_shmem;

	si = shmem_find(vi->shmid);
	if (si) {
		if (si->pid == SYSVIPC_SHMEM_PID) {
			pr_err("Shmem %"PRIx64" already collected as SYSVIPC\n", vi->shmid);
			return -1;
		}

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

	pr_info("Add new shmem 0x%"PRIx64" (%#016"PRIx64"-%#016"PRIx64")\n",
				vi->shmid, vi->start, vi->end);

	si->shmid = vi->shmid;
	si->pid	  = pid;
	si->size  = size;
	si->fd    = -1;
	si->count = 1;
	si->self_count = 1;
	futex_init(&si->lock);
	shmem_hash_add(si);

	return 0;
}

static int shmem_wait_and_open(struct shmem_info *si, VmaEntry *vi)
{
	char path[128];
	int ret;

	pr_info("Waiting for the %lx shmem to appear\n", si->shmid);
	futex_wait_while(&si->lock, 0);

	snprintf(path, sizeof(path), "/proc/%d/fd/%d",
		si->pid, si->fd);

	pr_info("Opening shmem [%s] \n", path);
	ret = open_proc_rw(si->pid, "fd/%d", si->fd);
	futex_inc_and_wake(&si->lock);
	if (ret < 0)
		return -1;

	vi->fd = ret;
	return 0;
}

static int do_restore_shmem_content(void *addr, unsigned long size, unsigned long shmid)
{
	int ret = 0;
	struct page_read pr;

	ret = open_page_read(shmid, &pr, PR_SHMEM);
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

		if (vaddr + nr_pages * PAGE_SIZE > size)
			break;

		pr.read_pages(&pr, vaddr, nr_pages, addr + vaddr, 0);
	}

	pr.close(&pr);
	return ret;
}

static int restore_shmem_content(void *addr, struct shmem_info *si)
{
	return do_restore_shmem_content(addr, si->size, si->shmid);
}

int restore_sysv_shmem_content(void *addr, unsigned long size, unsigned long shmid)
{
	return do_restore_shmem_content(addr, round_up(size, PAGE_SIZE), shmid);
}

static int open_shmem(int pid, struct vma_area *vma)
{
	VmaEntry *vi = vma->e;
	struct shmem_info *si;
	void *addr = MAP_FAILED;
	int f = -1;
	int flags;

	si = shmem_find(vi->shmid);
	pr_info("Search for %#016"PRIx64" shmem 0x%"PRIx64" %p/%d\n", vi->start, vi->shmid, si, si ? si->pid : -1);
	if (!si) {
		pr_err("Can't find my shmem %#016"PRIx64"\n", vi->start);
		return -1;
	}

	BUG_ON(si->pid == SYSVIPC_SHMEM_PID);

	if (si->pid != pid)
		return shmem_wait_and_open(si, vi);

	if (si->fd != -1) {
		f = dup(si->fd);
		if (f < 0) {
			pr_perror("Can't dup shmem fd");
			return -1;
		}

		goto out;
	}

	flags = MAP_SHARED;
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
out:
	vi->fd = f;
	return 0;
err:
	if (addr != MAP_FAILED)
		munmap(addr, si->size);
	close_safe(&f);
	return -1;
}

int add_shmem_area(pid_t pid, VmaEntry *vma, u64 *map)
{
	struct shmem_info *si;
	unsigned long size = vma->pgoff + (vma->end - vma->start);

	if (vma_entry_is(vma, VMA_AREA_SYSVIPC))
		pid = SYSVIPC_SHMEM_PID;

	si = shmem_find(vma->shmid);
	if (si) {
		if (si->size < size) {
			if (expand_shmem(si, size))
				return -1;
		}
		update_shmem_pmaps(si, map, vma);

		return 0;
	}

	si = xzalloc(sizeof(*si));
	if (!si)
		return -1;

	si->pid = pid;
	si->start = vma->start;
	si->end = vma->end;
	si->shmid = vma->shmid;
	shmem_hash_add(si);

	if (expand_shmem(si, size))
		return -1;
	update_shmem_pmaps(si, map, vma);

	return 0;
}

static int dump_pages(struct page_pipe *pp, struct page_xfer *xfer)
{
	struct page_pipe_buf *ppb;

	list_for_each_entry(ppb, &pp->bufs, l)
		if (vmsplice(ppb->p[1], ppb->iov, ppb->nr_segs,
					SPLICE_F_GIFT | SPLICE_F_NONBLOCK) !=
				ppb->pages_in * PAGE_SIZE) {
			pr_perror("Can't get shmem into page-pipe");
			return -1;
		}

	return page_xfer_dump_pages(xfer, pp);
}

static int next_data_segment(int fd, unsigned long pfn,
			unsigned long *next_data_pfn, unsigned long *next_hole_pfn)
{
	off_t off;

	off = lseek(fd, pfn * PAGE_SIZE, SEEK_DATA);
	if (off == (off_t) -1) {
		if (errno == ENXIO) {
			*next_data_pfn = ~0UL;
			*next_hole_pfn = ~0UL;
			return 0;
		}
		pr_perror("Unable to lseek(SEEK_DATA)");
		return -1;
	}
	*next_data_pfn = off / PAGE_SIZE;

	off = lseek(fd, off, SEEK_HOLE);
	if (off == (off_t) -1) {
		pr_perror("Unable to lseek(SEEK_HOLE)");
		return -1;
	}
	*next_hole_pfn = off / PAGE_SIZE;

	return 0;
}

static int do_dump_one_shmem(int fd, void *addr, struct shmem_info *si)
{
	struct page_pipe *pp;
	struct page_xfer xfer;
	int err, ret = -1;
	unsigned long pfn, nrpages, next_data_pnf = 0, next_hole_pfn = 0;

	nrpages = (si->size + PAGE_SIZE - 1) / PAGE_SIZE;

	pp = create_page_pipe((nrpages + 1) / 2, NULL, PP_CHUNK_MODE);
	if (!pp)
		goto err;

	err = open_page_xfer(&xfer, CR_FD_SHMEM_PAGEMAP, si->shmid);
	if (err)
		goto err_pp;

	xfer.offset = (unsigned long)addr;

	for (pfn = 0; pfn < nrpages; pfn++) {
		unsigned int pgstate = PST_DIRTY;
		bool use_mc = true;
		unsigned long pgaddr;

		if (pfn >= next_hole_pfn &&
		    next_data_segment(fd, pfn, &next_data_pnf, &next_hole_pfn))
			goto err_xfer;

		if (si->pstate_map && is_shmem_tracking_en()) {
			pgstate = get_pstate(si->pstate_map, pfn);
			use_mc = pgstate == PST_DONT_DUMP;
		}

		if (use_mc) {
			if (pfn < next_data_pnf)
				pgstate = PST_ZERO;
			else
				pgstate = PST_DIRTY;
		}

		pgaddr = (unsigned long)addr + pfn * PAGE_SIZE;
again:
		if (pgstate == PST_ZERO)
			ret = 0;
		else if (xfer.parent && page_in_parent(pgstate == PST_DIRTY))
			ret = page_pipe_add_hole(pp, pgaddr, PP_HOLE_PARENT);
		else
			ret = page_pipe_add_page(pp, pgaddr, 0);

		if (ret == -EAGAIN) {
			ret = dump_pages(pp, &xfer);
			if (ret)
				goto err_xfer;
			page_pipe_reinit(pp);
			goto again;
		} else if (ret)
			goto err_xfer;
	}

	ret = dump_pages(pp, &xfer);

err_xfer:
	xfer.close(&xfer);
err_pp:
	destroy_page_pipe(pp);
err:
	return ret;
}

static int dump_one_shmem(struct shmem_info *si)
{
	int fd, ret = -1;
	void *addr;

	pr_info("Dumping shared memory %ld\n", si->shmid);

	fd = open_proc(si->pid, "map_files/%lx-%lx", si->start, si->end);
	if (fd < 0)
		goto err;

	addr = mmap(NULL, si->size, PROT_READ, MAP_SHARED, fd, 0);
	if (addr == MAP_FAILED) {
		pr_err("Can't map shmem 0x%lx (0x%lx-0x%lx)\n",
				si->shmid, si->start, si->end);
		goto errc;
	}

	ret = do_dump_one_shmem(fd, addr, si);

	munmap(addr, si->size);
errc:
	close(fd);
err:
	return ret;
}

int dump_one_sysv_shmem(void *addr, unsigned long size, unsigned long shmid)
{
	int fd, ret;
	struct shmem_info *si, det;

	si = shmem_find(shmid);
	if (!si) {
		pr_info("Detached shmem...\n");
		det.pid = SYSVIPC_SHMEM_PID;
		det.shmid = shmid;
		det.size = round_up(size, PAGE_SIZE);
		det.pstate_map = NULL;
		si = &det;
	}

	fd = open_proc(PROC_SELF, "map_files/%lx-%lx",
			(unsigned long)addr, (unsigned long)addr + si->size);
	if (fd < 0)
		return -1;

	ret = do_dump_one_shmem(fd, addr, si);
	close(fd);
	return ret;
}

int cr_dump_shmem(void)
{
	int ret = 0, i;
	struct shmem_info *si;

	for_each_shmem(i, si) {
		if (si->pid == SYSVIPC_SHMEM_PID)
			continue;
		ret = dump_one_shmem(si);
		if (ret)
			goto out;
	}
out:
	return ret;
}
