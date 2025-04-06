#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>

#include "page.h"
#include "pagemap-cache.h"
#include "common/compiler.h"
#include "xmalloc.h"
#include "util.h"
#include "log.h"
#include "vma.h"
#include "mem.h"
#include "kerndat.h"
#include "fault-injection.h"

#undef LOG_PREFIX
#define LOG_PREFIX "pagemap-cache: "

/* To carry up to 2M of physical memory */
#define PMC_SHIFT    (21)
#define PMC_SIZE     (1ul << PMC_SHIFT)
#define PMC_MASK     (~(PMC_SIZE - 1))
#define PMC_SIZE_GAP (PMC_SIZE / 4)

#define PAGEMAP_LEN(addr) (PAGE_PFN(addr) * sizeof(u64))

#define PAGE_REGIONS_MAX_NR 32768

/*
 * It's a workaround for a kernel bug. In the 3.19 kernel when pagemap are read
 * for a few vma-s for one read call, it returns incorrect data.
 * https://github.com/checkpoint-restore/criu/issues/207
*/
static bool pagemap_cache_disabled;

static inline void pmc_reset(pmc_t *pmc)
{
	memzero(pmc, sizeof(*pmc));
	pmc->fd = -1;
}

static inline void pmc_zap(pmc_t *pmc)
{
	pmc->start = pmc->end = 0;
}

int pmc_init(pmc_t *pmc, pid_t pid, const struct list_head *vma_head, size_t size)
{
	size_t map_size = max(size, (size_t)PMC_SIZE);
	pmc_reset(pmc);

	BUG_ON(!vma_head);

	pmc->pid = pid;
	pmc->map_len = PAGEMAP_LEN(map_size);
	pmc->vma_head = vma_head;
	pmc->regs_max_len = PAGE_PFN(map_size);
	if (pmc->regs_max_len > PAGE_REGIONS_MAX_NR)
		pmc->regs_max_len = PAGE_REGIONS_MAX_NR;
	pmc->regs_len = 0;
	pmc->regs_idx = 0;
	pmc->regs = NULL;
	pmc->map = NULL;

	if (kdat.has_pagemap_scan && !fault_injected(FI_DONT_USE_PAGEMAP_SCAN)) {
		pmc->regs = xmalloc(pmc->regs_max_len * sizeof(struct page_region));
		if (!pmc->regs)
			goto err;
	} else {
		pmc->map = xmalloc(pmc->map_len);
		if (!pmc->map)
			goto err;
	}

	if (pagemap_cache_disabled)
		pr_warn_once("The pagemap cache is disabled\n");

	if (kdat.pmap == PM_DISABLED) {
		/*
		 * FIXME We might need to implement greedy
		 * mode via reading all pages available inside
		 * parasite.
		 *
		 * Actually since linux-4.4 the pagemap file
		 * is available for usernamespace with hiding
		 * PFNs but providing page attributes, so other
		 * option simply require kernel 4.4 and above
		 * for usernamespace support.
		 */
		pr_err("No pagemap for %d available\n", pid);
		goto err;
	} else {
		pmc->fd = open_proc(pid, "pagemap");
		if (pmc->fd < 0)
			goto err;
	}

	pr_debug("created for pid %d (takes %zu bytes)\n", pid, pmc->map_len);
	return 0;

err:
	pr_err("Failed to init pagemap for %d\n", pid);
	pmc_fini(pmc);
	return -1;
}

static int pmc_fill_cache(pmc_t *pmc, const struct vma_area *vma)
{
	unsigned long low = vma->e->start & PMC_MASK;
	unsigned long high = low + PMC_SIZE;
	size_t len = vma_area_len(vma);

	if (high > kdat.task_size)
		high = kdat.task_size;

	pmc->start = vma->e->start;
	pmc->end = vma->e->end;

	pr_debug("%d: filling VMA %lx-%lx (%zuK) [l:%lx h:%lx]\n", pmc->pid, (long)vma->e->start, (long)vma->e->end,
		 len >> 10, low, high);

	/*
	 * If we meet a small VMA, lets try to fit 2M cache
	 * window at least 75% full, otherwise left as a plain
	 * "one vma at a time" read. Note the VMAs in cache must
	 * fit in solid manner, iow -- either the whole vma fits
	 * the cache window, either plain read is used.
	 *
	 * The benefit (apart reducing the number of read() calls)
	 * is to walk page tables less.
	 */
	if (!pagemap_cache_disabled && len < PMC_SIZE && (vma->e->start - low) < PMC_SIZE_GAP) {
		size_t size_cov = len;
		size_t nr_vmas = 1;

		pr_debug("\t%d: %16lx-%-16lx nr:%-5zu cov:%zu\n", pmc->pid, (long)vma->e->start, (long)vma->e->end,
			 nr_vmas, size_cov);

		list_for_each_entry_continue(vma, pmc->vma_head, list) {
			if (vma->e->start > high || vma->e->end > high)
				break;

			BUG_ON(vma->e->start < low);
			size_cov += vma_area_len(vma);
			nr_vmas++;

			pr_debug("\t%d: %16lx-%-16lx nr:%-5zu cov:%zu\n", pmc->pid, (long)vma->e->start,
				 (long)vma->e->end, nr_vmas, size_cov);
		}

		if (nr_vmas > 1) {
			/*
			 * Note we don't touch low bound since it's set
			 * to first VMA start already and not updating it
			 * allows us to save a couple of code bytes.
			 */
			pmc->end = high;
			pr_debug("\t%d: cache  mode [l:%lx h:%lx]\n", pmc->pid, pmc->start, pmc->end);
		} else
			pr_debug("\t%d: simple mode [l:%lx h:%lx]\n", pmc->pid, pmc->start, pmc->end);
	}

	return pmc_fill(pmc, pmc->start, pmc->end);
}

int pmc_fill(pmc_t *pmc, u64 start, u64 end)
{
	size_t size_map, off;

	pmc->start = start;
	pmc->end = end;

	size_map = PAGEMAP_LEN(pmc->end - pmc->start);
	BUG_ON(pmc->map_len < size_map);
	BUG_ON(pmc->fd < 0);

	if (pmc->regs) {
		struct pm_scan_arg args = {
			.size = sizeof(struct pm_scan_arg),
			.flags = 0,
			.start = pmc->start,
			.end = pmc->end,
			.vec = (long)pmc->regs,
			.vec_len = pmc->regs_max_len,
			.max_pages = 0,
			/*
			 * Request pages that are in  RAM or swap, excluding
			 * zero-filled and file-backed pages.
			 */
			.category_inverted = PAGE_IS_PFNZERO | PAGE_IS_FILE,
			.category_mask = PAGE_IS_PFNZERO | PAGE_IS_FILE,
			.category_anyof_mask = PAGE_IS_PRESENT | PAGE_IS_SWAPPED,
			.return_mask = PAGE_IS_PRESENT | PAGE_IS_SWAPPED | PAGE_IS_SOFT_DIRTY,
		};
		long ret;

		if (kdat.has_pagemap_scan_guard_pages)
			args.return_mask |= PAGE_IS_GUARD;

		ret = ioctl(pmc->fd, PAGEMAP_SCAN, &args);
		if (ret == -1) {
			pr_perror("PAGEMAP_SCAN");
			pmc_zap(pmc);
			return -1;
		}
		pmc->regs_len = ret;
		pmc->regs_idx = 0;
		pmc->end = args.walk_end;
	} else {
		for (off = 0; off != size_map;) {
			ssize_t ret;
			char *ptr = (char *)pmc->map;

			ret = pread(pmc->fd, ptr + off, size_map - off, PAGEMAP_PFN_OFF(pmc->start) + off);
			if (ret == -1) {
				pmc_zap(pmc);
				pr_perror("Can't read %d's pagemap file", pmc->pid);
				return -1;
			}
			off += ret;
		}
	}

	return 0;
}

int pmc_get_map(pmc_t *pmc, const struct vma_area *vma)
{
	/* Hit */
	if (likely(pmc->start <= vma->e->start && pmc->end >= vma->e->end))
		return 0;

	/* Miss, refill the cache */
	if (pmc_fill_cache(pmc, vma)) {
		pr_err("Failed to fill cache for %d (%lx-%lx)\n", pmc->pid, (long)vma->e->start, (long)vma->e->end);
		return -1;
	}
	return 0;
}

void pmc_fini(pmc_t *pmc)
{
	close_safe(&pmc->fd);
	xfree(pmc->map);
	xfree(pmc->regs);
	pmc_reset(pmc);
}

static void __attribute__((constructor)) pagemap_cache_init(void)
{
	pagemap_cache_disabled = (getenv("CRIU_PMC_OFF") != NULL);
}
