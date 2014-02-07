#ifndef __CR_VMA_H__
#define __CR_VMA_H__

#include "list.h"
#include "protobuf/vma.pb-c.h"

struct vm_area_list {
	struct list_head	h;
	unsigned		nr;
	unsigned long		priv_size; /* nr of pages in private VMAs */
	unsigned long		longest; /* nr of pages in longest VMA */
};

#define VM_AREA_LIST(name)	struct vm_area_list name = { .h = LIST_HEAD_INIT(name.h), .nr = 0, }

static inline void vm_area_list_init(struct vm_area_list *vml)
{
	INIT_LIST_HEAD(&vml->h);
	vml->nr = 0;
	vml->priv_size = 0;
	vml->longest = 0;
}

struct file_desc;

struct vma_area {
	struct list_head	list;
	VmaEntry		*e;

	union {
		int		vm_file_fd;
		int		vm_socket_id;
		struct file_desc *fd;
	};
	unsigned long		*page_bitmap;  /* existent pages */
	unsigned long		*ppage_bitmap; /* parent's existent pages */

	unsigned long		premmaped_addr;

	bool			file_borrowed;

	struct stat		*st;
};

extern struct vma_area *alloc_vma_area(void);
extern int collect_mappings(pid_t pid, struct vm_area_list *vma_area_list);
extern void free_mappings(struct vm_area_list *vma_area_list);
extern bool privately_dump_vma(struct vma_area *vma);

#define vma_area_is(vma_area, s)	vma_entry_is((vma_area)->e, s)
#define vma_area_len(vma_area)		vma_entry_len((vma_area)->e)
#define vma_entry_is(vma, s)		(((vma)->status & (s)) == (s))
#define vma_entry_len(vma)		((vma)->end - (vma)->start)

/*
 * vma_premmaped_start() can be used only in restorer.
 * In other cases vma_area->premmaped_addr must be used.
 * This hack is required, because vma_area isn't tranfered in restorer and
 * shmid is used to determing which vma-s are cowed.
 */
#define vma_premmaped_start(vma)	((vma)->shmid)

static inline int in_vma_area(struct vma_area *vma, unsigned long addr)
{
	return addr >= (unsigned long)vma->e->start &&
		addr < (unsigned long)vma->e->end;
}

#endif /* __CR_VMA_H__ */
