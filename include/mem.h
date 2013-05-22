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
#define PME_PSHIFT_BITS		(6)
#define PME_STATUS_BITS		(3)
#define PME_STATUS_OFFSET	(64 - PME_STATUS_BITS)
#define PME_PSHIFT_OFFSET	(PME_STATUS_OFFSET - PME_PSHIFT_BITS)
#define PME_PFRAME_MASK		((1ULL << PME_PSHIFT_OFFSET) - 1)
#define PME_PFRAME(x)		((x) & PME_PFRAME_MASK)

#endif /* __CR_MEM_H__ */
