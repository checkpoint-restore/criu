#ifndef __CR_IMAGE_H__
#define __CR_IMAGE_H__

#include <stdbool.h>

#include "compiler.h"
#include "image-desc.h"
#include "magic.h"

#define PAGE_IMAGE_SIZE	4096
#define PAGE_RSS	1
#define PAGE_ANON	2

/*
 * Top bit set in the tgt id means we've remapped
 * to a ghost file.
 */
#define REMAP_GHOST	(1 << 31)

#define USK_EXTERN	(1 << 0)

#define VMA_AREA_NONE		(0 <<  0)
#define VMA_AREA_REGULAR	(1 <<  0)	/* Dumpable area */
#define VMA_AREA_STACK		(1 <<  1)
#define VMA_AREA_VSYSCALL	(1 <<  2)
#define VMA_AREA_VDSO		(1 <<  3)
#define VMA_FORCE_READ		(1 <<  4)	/* VMA changed to be readable */
#define VMA_AREA_HEAP		(1 <<  5)

#define VMA_FILE_PRIVATE	(1 <<  6)
#define VMA_FILE_SHARED		(1 <<  7)
#define VMA_ANON_SHARED		(1 <<  8)
#define VMA_ANON_PRIVATE	(1 <<  9)

#define VMA_AREA_SYSVIPC	(1 <<  10)
#define VMA_AREA_SOCKET		(1 <<  11)

#define vma_premmaped_start(vma) ((vma)->shmid)
#define vma_entry_is(vma, s)	(((vma)->status & (s)) == (s))
#define vma_entry_len(vma)	((vma)->end - (vma)->start)

#define CR_CAP_SIZE	2

#define TASK_COMM_LEN 16

#define TASK_ALIVE		0x1
#define TASK_DEAD		0x2
#define TASK_STOPPED		0x3 /* FIXME - implement */
#define TASK_HELPER		0x4

extern bool fdinfo_per_id;

#endif /* __CR_IMAGE_H__ */
