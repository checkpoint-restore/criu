#include <unistd.h>
#include <stdio.h>
#include <stdbool.h>
#include "vma.h"
#include "xmalloc.h"
#include "pstree.h"
#include "restorer.h"
#include "aio.h"
#include "rst_info.h"
#include "rst-malloc.h"
#include "parasite.h"
#include "parasite-syscall.h"
#include "images/mm.pb-c.h"

#define NR_IOEVENTS_IN_NPAGES(npages) ((PAGE_SIZE * npages - sizeof(struct aio_ring)) / sizeof(struct io_event))

int dump_aio_ring(MmEntry *mme, struct vma_area *vma)
{
	int nr = mme->n_aios;
	AioRingEntry *re;

	mme->aios = xrealloc(mme->aios, (nr + 1) * sizeof(re));
	if (!mme->aios)
		return -1;

	re = xmalloc(sizeof(*re));
	if (!re)
		return -1;

	aio_ring_entry__init(re);
	re->id = vma->e->start;
	re->ring_len = vma->e->end - vma->e->start;
	re->nr_req = aio_estimate_nr_reqs(re->ring_len);
	if (!re->nr_req)
		return -1;
	mme->aios[nr] = re;
	mme->n_aios = nr + 1;
	pr_info("Dumping AIO ring @%"PRIx64"-%"PRIx64"\n",
		vma->e->start, vma->e->end);
	return 0;
}

void free_aios(MmEntry *mme)
{
	int i;

	if (mme->aios) {
		for (i = 0; i < mme->n_aios; i++)
			xfree(mme->aios[i]);
		xfree(mme->aios);
	}
}

unsigned int aio_estimate_nr_reqs(unsigned int size)
{
	unsigned int k_max_reqs = NR_IOEVENTS_IN_NPAGES(size/PAGE_SIZE);

	if (size & ~PAGE_MASK) {
		pr_err("Ring size is not aligned\n");
		return 0;
	}
	/*
	 * Kernel does
	 *
	 * nr_reqs = max(nr_reqs, nr_cpus * 4)
	 * nr_reqs *= 2
	 * nr_reqs += 2
	 * ring = roundup(sizeof(head) + nr_reqs * sizeof(req))
	 * nr_reqs = (ring - sizeof(head)) / sizeof(req)
	 *
	 * And the k_max_reqs here is the resulting value.
	 *
	 * We need to get the initial nr_reqs that would grow
	 * up back to the k_max_reqs.
	 */

	return (k_max_reqs - 2) / 2;
}

unsigned long aio_rings_args_size(struct vm_area_list *vmas)
{
	return sizeof(struct parasite_check_aios_args) +
		vmas->nr_aios * sizeof(struct parasite_aio);
}

int parasite_collect_aios(struct parasite_ctl *ctl, struct vm_area_list *vmas)
{
	struct vma_area *vma;
	struct parasite_check_aios_args *aa;
	struct parasite_aio *pa;

	if (!vmas->nr_aios)
		return 0;

	pr_info("Checking AIO rings\n");

	/*
	 * Go to parasite and
	 * a) check that no requests are currently pengind
	 * b) get the maximum number of requests kernel handles
	 *    to estimate what was the user request on ring
	 *    creation.
	 */

	aa = parasite_args_s(ctl, aio_rings_args_size(vmas));
	pa = &aa->ring[0];
	list_for_each_entry(vma, &vmas->h, list) {
		if (!vma_area_is(vma, VMA_AREA_AIORING))
			continue;

		pr_debug(" `- Ring #%ld @%"PRIx64"\n",
				(long)(pa - &aa->ring[0]), vma->e->start);
		pa->ctx = vma->e->start;
		pa->size = vma->e->end - vma->e->start;
		pa++;
	}
	aa->nr_rings = vmas->nr_aios;

	if (parasite_execute_daemon(PARASITE_CMD_CHECK_AIOS, ctl))
		return -1;

	return 0;
}

int prepare_aios(struct pstree_item *t, struct task_restore_args *ta)
{
	int i;
	MmEntry *mm = rsti(t)->mm;
	/*
	 * Put info about AIO rings, they will get remapped
	 */

	ta->rings = (struct rst_aio_ring *)rst_mem_align_cpos(RM_PRIVATE);
	ta->rings_n = mm->n_aios;

	for (i = 0; i < mm->n_aios; i++) {
		struct rst_aio_ring *raio;

		raio = rst_mem_alloc(sizeof(*raio), RM_PRIVATE);
		if (!raio)
			return -1;

		raio->addr = mm->aios[i]->id;
		raio->nr_req = mm->aios[i]->nr_req;
		raio->len = mm->aios[i]->ring_len;
	}

	return 0;
}
