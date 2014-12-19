#ifndef __CR_AIO_H__
#define __CR_AIO_H__
#include "protobuf/mm.pb-c.h"
int dump_aio_ring(MmEntry *mme, struct vma_area *vma);
void free_aios(MmEntry *mme);
struct parasite_ctl;
int parasite_check_aios(struct parasite_ctl *, struct vm_area_list *);
unsigned long aio_rings_args_size(struct vm_area_list *);
#endif /* __CR_AIO_H__ */
