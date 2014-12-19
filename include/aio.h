#ifndef __CR_AIO_H__
#define __CR_AIO_H__
#include "protobuf/mm.pb-c.h"
int dump_aio_ring(MmEntry *mme, struct vma_area *vma);
void free_aios(MmEntry *mme);
struct parasite_ctl;
int parasite_check_aios(struct parasite_ctl *, struct vm_area_list *);
unsigned long aio_rings_args_size(struct vm_area_list *);

struct rst_aio_ring {
	unsigned long addr;
	unsigned long len;
	unsigned int nr_req;
};
#endif /* __CR_AIO_H__ */
