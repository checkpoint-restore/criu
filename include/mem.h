#ifndef __CR_MEM_H__
#define __CR_MEM_H__

struct parasite_ctl;
struct vm_area_list;
struct page_pipe;

extern int do_task_reset_dirty_track(int pid);
extern unsigned int dump_pages_args_size(struct vm_area_list *vmas);
extern int parasite_dump_pages_seized(struct parasite_ctl *ctl,
				      struct vm_area_list *vma_area_list,
				      struct page_pipe **pp);

#endif /* __CR_MEM_H__ */
