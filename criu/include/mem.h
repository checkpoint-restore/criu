#ifndef __CR_MEM_H__
#define __CR_MEM_H__

#include <stdbool.h>
#include "int.h"
#include "vma.pb-c.h"
#include "pid.h"
#include "proc_parse.h"
#include "inventory.pb-c.h"
#include "pagemap-cache.h"

struct parasite_ctl;
struct vm_area_list;
struct page_pipe;
struct pstree_item;
struct vma_area;

struct mem_dump_ctl {
	bool pre_dump;
	bool lazy;
	struct proc_pid_stat *stat;
	InventoryEntry *parent_ie;
};

extern bool vma_has_guard_gap_hidden(struct vma_area *vma);
extern bool page_is_zero(u64 pme);
extern bool page_in_parent(bool dirty);
extern int prepare_mm_pid(struct pstree_item *i);
extern void prepare_cow_vmas(void);
extern int do_task_reset_dirty_track(int pid);
extern unsigned long dump_pages_args_size(struct vm_area_list *vmas);
extern int parasite_dump_pages_seized(struct pstree_item *item, struct vm_area_list *vma_area_list,
				      struct mem_dump_ctl *mdc, struct parasite_ctl *ctl);
extern int collect_madv_guards(pid_t pid, struct vm_area_list *vma_area_list);

#define PME_PRESENT	  (1ULL << 63)
#define PME_SWAP	  (1ULL << 62)
#define PME_FILE	  (1ULL << 61)
#define PME_GUARD_REGION  (1ULL << 58)
#define PME_SOFT_DIRTY	  (1ULL << 55)
#define PME_PSHIFT_BITS	  (6)
#define PME_STATUS_BITS	  (3)
#define PME_STATUS_OFFSET (64 - PME_STATUS_BITS)
#define PME_PSHIFT_OFFSET (PME_STATUS_OFFSET - PME_PSHIFT_BITS)
#define PME_PFRAME_MASK	  ((1ULL << PME_PSHIFT_OFFSET) - 1)
#define PME_PFRAME(x)	  ((x)&PME_PFRAME_MASK)

struct task_restore_args;
int open_vmas(struct pstree_item *t);
int prepare_vmas(struct pstree_item *t, struct task_restore_args *ta);
int unmap_guard_pages(struct pstree_item *t);
int prepare_mappings(struct pstree_item *t);

struct page_info {
	u64 next;
	bool softdirty;
};

int should_dump_page(pmc_t *pmc, VmaEntry *vmae, u64 vaddr, struct page_info *page_info);

#endif /* __CR_MEM_H__ */
