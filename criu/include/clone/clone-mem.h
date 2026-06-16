#ifndef __CR_CLONE_MEM_H__
#define __CR_CLONE_MEM_H__

#include <stdbool.h>
#include "int.h"
#include "common/list.h"
#include "vma.h"

#ifdef CONFIG_HAS_LZ4

struct lazy_vma_entry {
	uint64_t start;
	uint64_t end;
	struct list_head list;
	struct vma_area *vma;
	unsigned long total_pages;    /* Total pages in this VMA */
	u64 dst_id;                   /* Process identifier for this VMA */
	pid_t source_pid;             /* PID for process_vm_readv */
};

/* Global lazy VMA list management */
extern struct list_head *clone_mem_get_lazy_vmas(void);
extern void clone_mem_init_lazy_vmas(void);
extern void clone_mem_free_lazy_vmas(void);

/* Lazy VMA lookup functions */
extern unsigned long clone_mem_count_lazy_vma_pages(u64 dst_id);
extern int clone_mem_add_lazy_vma_range(unsigned long start, unsigned long len,
				       u64 dst_id, pid_t source_pid);

/* Add a lazy VMA entry during dump (called from generate_iovs in mem.c) */
extern int clone_mem_add_lazy_vma(struct vma_area *vma, unsigned long nr_pages,
				u64 dst_id, pid_t source_pid);

#else /* !CONFIG_HAS_LZ4 */

/* Stubs when LZ4/CLONE support is not compiled in */
static inline struct list_head *clone_mem_get_lazy_vmas(void) { return NULL; }
static inline void clone_mem_init_lazy_vmas(void) { }
static inline void clone_mem_free_lazy_vmas(void) { }
static inline unsigned long clone_mem_count_lazy_vma_pages(u64 dst_id)
{
	(void)dst_id;
	return 0;
}
static inline int clone_mem_add_lazy_vma_range(unsigned long start, unsigned long len,
					       u64 dst_id, pid_t source_pid)
{
	(void)start; (void)len; (void)dst_id; (void)source_pid;
	return -1;
}
static inline int clone_mem_add_lazy_vma(struct vma_area *vma, unsigned long nr_pages,
					 u64 dst_id, pid_t source_pid)
{
	(void)vma; (void)nr_pages; (void)dst_id; (void)source_pid;
	return -1;
}

#endif /* CONFIG_HAS_LZ4 */

#endif /* __CR_CLONE_MEM_H__ */
