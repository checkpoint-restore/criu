#ifndef __CR_VMA_H__
#define __CR_VMA_H__

#include "asm/types.h"
#include "image.h"
#include "list.h"

#include "images/vma.pb-c.h"

struct vm_area_list {
	struct list_head	h;
	unsigned		nr;
	unsigned int		nr_aios;
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
		struct /* for dump */ {
			union {
				/*
				 * These two cannot be assigned at once.
				 * The file_fd is an fd for a regular file and
				 * the socket_id is the inode number of the
				 * mapped (PF_PACKET) socket.
				 *
				 * The aio_nr_req is only for aio rings.
				 */
				int	vm_file_fd;
				int	vm_socket_id;
				unsigned int aio_nr_req;
			};

			char		*aufs_rpath;	/* path from aufs root */
			char		*aufs_fpath;	/* full path from global root */

			/*
			 * When several subsequent vmas have the same 
			 * dev:ino pair all 'tail' ones set this to true
			 * and the vmst points to the head's stat buf.
			 */
			bool		file_borrowed;
			struct stat	*vmst;
			int		mnt_id;
		};

		struct /* for restore */ {
			struct file_desc *vmfd;
			unsigned long	*page_bitmap;	/* existent pages */
			unsigned long	*ppage_bitmap;	/* parent's existent pages */
			unsigned long	premmaped_addr;	/* restore only */
		};
	};
};

extern struct vma_area *alloc_vma_area(void);
extern int collect_mappings(pid_t pid, struct vm_area_list *vma_area_list);
extern void free_mappings(struct vm_area_list *vma_area_list);

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

static inline bool vma_entry_is_private(VmaEntry *entry,
					unsigned long task_size)
{
	return (vma_entry_is(entry, VMA_AREA_REGULAR)	&&
		(vma_entry_is(entry, VMA_ANON_PRIVATE)	||
		 vma_entry_is(entry, VMA_FILE_PRIVATE)) &&
		 (entry->end <= task_size)) ||
		vma_entry_is(entry, VMA_AREA_AIORING);
}

static inline bool vma_area_is_private(struct vma_area *vma,
				       unsigned long task_size)
{
	return vma_entry_is_private(vma->e, task_size);
}

#endif /* __CR_VMA_H__ */
