#ifndef __CR_AIO_H__
#define __CR_AIO_H__

#include <linux/aio_abi.h>
#include "images/mm.pb-c.h"
unsigned int aio_estimate_nr_reqs(unsigned int size);
int dump_aio_ring(MmEntry *mme, struct vma_area *vma);
void free_aios(MmEntry *mme);
struct parasite_ctl;
int parasite_collect_aios(struct parasite_ctl *, struct vm_area_list *);
unsigned long aio_rings_args_size(struct vm_area_list *);
struct task_restore_args;
int prepare_aios(struct pstree_item *t, struct task_restore_args *ta);

struct aio_ring {
	unsigned id;   /* kernel internal index number */
	unsigned nr;   /* number of io_events */
	unsigned head; /* Written to by userland or under ring_lock
				 * mutex by aio_read_events_ring(). */
	unsigned tail;

	unsigned magic;
	unsigned compat_features;
	unsigned incompat_features;
	unsigned header_length; /* size of aio_ring */

	struct io_event io_events[0];
};

struct rst_aio_ring {
	unsigned long addr;
	unsigned long len;
	unsigned int nr_req;
};
#endif /* __CR_AIO_H__ */
