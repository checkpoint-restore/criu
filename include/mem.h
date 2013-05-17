#ifndef __CR_MEM_H__
#define __CR_MEM_H__
struct vm_area_list;
int do_task_reset_dirty_track(int pid);
unsigned int dump_pages_args_size(struct vm_area_list *vmas);
struct parasite_ctl;
struct page_pipe;
int parasite_dump_pages_seized(struct parasite_ctl *ctl,
		struct vm_area_list *vma_area_list, struct page_pipe **pp);
#endif
