/*
 * CLONE memory tracking for lazy page migration.
 *
 * Global lazy VMA list management and convergence mode handling
 * for CLONE dump operations.
 */

#include <pthread.h>

#include "types.h"
#include "cr_options.h"
#include "clone/clone-mem.h"
#include "log.h"
#include "xmalloc.h"
#include "clone/atomic-bitmap.h"
#include "page-xfer.h"

/* Global lazy VMA list for CLONE dump */
static LIST_HEAD(global_lazy_vmas);
static pthread_spinlock_t lazy_vmas_lock;
static pthread_once_t lazy_vmas_lock_once = PTHREAD_ONCE_INIT;

static void init_lazy_vmas_lock_once(void)
{
	pthread_spin_init(&lazy_vmas_lock, PTHREAD_PROCESS_PRIVATE);
}

void clone_mem_init_lazy_vmas(void)
{
	pthread_once(&lazy_vmas_lock_once, init_lazy_vmas_lock_once);
}

struct list_head *clone_mem_get_lazy_vmas(void)
{
	return &global_lazy_vmas;
}


/*
 * clone_mem_add_lazy_vma_range - Add a new VMA to global_lazy_vmas
 *
 * Called from Phase 3 when new VMAs are detected that weren't present
 * in Phase 1. These need to be added to global_lazy_vmas so the page
 * server can iterate through them during page transfer.
 *
 * @start: VMA start address
 * @len: VMA length in bytes
 * @dst_id: Process identifier for page transfer
 * @source_pid: PID for process_vm_readv
 *
 * Returns: 0 on success, -1 on error
 */
int clone_mem_add_lazy_vma_range(unsigned long start, unsigned long len,
				u64 dst_id, pid_t source_pid)
{
	struct lazy_vma_entry *lve;
	unsigned long nr_pages;

	lve = xmalloc(sizeof(*lve));
	if (!lve)
		return -1;

	clone_mem_init_lazy_vmas();

	nr_pages = len / PAGE_SIZE;
	lve->start = start;
	lve->end = start + len;
	lve->total_pages = nr_pages;
	lve->dst_id = dst_id;
	lve->source_pid = source_pid;
	lve->vma = NULL;  /* No vma_area for Phase 3 discovered regions */

	pthread_spin_lock(&lazy_vmas_lock);
	list_add_tail(&lve->list, &global_lazy_vmas);
	pthread_spin_unlock(&lazy_vmas_lock);

	pr_info("Added lazy VMA for new region 0x%lx-0x%lx "
		"(%lu pages, dst_id=%lu, pid=%d)\n",
		start, start + len, nr_pages,
		(unsigned long)dst_id, source_pid);

	return 0;
}

/*
 * clone_mem_add_lazy_vma - Add a lazy VMA entry during dump
 *
 * Called from generate_iovs() in mem.c when CLONE dump is enabled and
 * the VMA is lazy-capable. This adds the VMA to the global list for
 * later page transfer.
 *
 * @vma: VMA area being processed
 * @nr_pages: Number of pages in the VMA
 * @dst_id: Process identifier (vpid)
 * @source_pid: Real PID for process_vm_readv
 *
 * Returns: 0 on success, -1 on error
 */
int clone_mem_add_lazy_vma(struct vma_area *vma, unsigned long nr_pages,
			 u64 dst_id, pid_t source_pid)
{
	struct lazy_vma_entry *lve;

	lve = xmalloc(sizeof(*lve));
	if (!lve)
		return -1;

	/* Initialize global list on first use */
	clone_mem_init_lazy_vmas();

	lve->vma = vma;
	lve->total_pages = nr_pages;
	lve->dst_id = dst_id;
	lve->source_pid = source_pid;
	lve->start = vma->e->start;
	lve->end = vma->e->end;

	/* Add to global list (thread-safe) */
	pthread_spin_lock(&lazy_vmas_lock);
	list_add_tail(&lve->list, &global_lazy_vmas);
	pthread_spin_unlock(&lazy_vmas_lock);

	pr_debug("Added lazy VMA 0x%llx-0x%llx to global list "
		"(%lu pages, dst_id=%lu, pid=%d)\n",
		(unsigned long long)vma->e->start,
		(unsigned long long)vma->e->end, nr_pages,
		(unsigned long)dst_id, source_pid);

	return 0;
}

/* Count total pages in lazy VMAs for a given dst_id (exported for page-xfer.c) */
unsigned long clone_mem_count_lazy_vma_pages(u64 dst_id)
{
	struct lazy_vma_entry *lve;
	unsigned long total_pages = 0;

	/* Ensure lock is initialized (pthread_once guarantees single init) */
	clone_mem_init_lazy_vmas();

	pthread_spin_lock(&lazy_vmas_lock);
	list_for_each_entry(lve, &global_lazy_vmas, list) {
		if (lve->dst_id == dst_id)
			total_pages += lve->total_pages;
	}
	pthread_spin_unlock(&lazy_vmas_lock);

	return total_pages;
}


/* Cleanup function for global lazy VMA list */
void clone_mem_free_lazy_vmas(void)
{
	struct lazy_vma_entry *lve, *tmp;

	/* If list is empty, nothing to free and lock may not be initialized */
	if (list_empty(&global_lazy_vmas))
		return;

	/* Init ensures lock is ready (pthread_once guarantees single init) */
	clone_mem_init_lazy_vmas();

	pthread_spin_lock(&lazy_vmas_lock);
	list_for_each_entry_safe(lve, tmp, &global_lazy_vmas, list) {
		list_del(&lve->list);
		xfree(lve);
	}
	pthread_spin_unlock(&lazy_vmas_lock);
}
