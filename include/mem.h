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

#define PME_PRESENT		(1ULL << 63)
#define PME_SWAP		(1ULL << 62)
#define PME_FILE		(1ULL << 61)
#define PME_SOFT_DIRTY		(1ULL << 55)

#endif /* __CR_MEM_H__ */
