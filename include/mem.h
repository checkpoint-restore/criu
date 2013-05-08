#ifndef __CR_MEM_H__
#define __CR_MEM_H__
struct vm_area_list;
unsigned int vmas_pagemap_size(struct vm_area_list *vmas);
struct parasite_ctl;
int parasite_dump_pages_seized(struct parasite_ctl *ctl,
		struct vm_area_list *vma_area_list);
#endif
