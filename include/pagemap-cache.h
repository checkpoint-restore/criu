#ifndef __CR_PAGEMAP_H__
#define __CR_PAGEMAP_H__

#include <sys/types.h>
#include "asm-generic/page.h"
#include "asm/int.h"

#include "list.h"

struct vma_area;

#define PAGEMAP_PFN_OFF(addr)	(PAGE_PFN(addr) * sizeof(u64))

typedef struct {
	pid_t			pid;		/* which process it belongs */
	unsigned long		start;		/* start of area */
	unsigned long		end;		/* end of area */
	struct list_head	*vma_head;	/* list head of VMAs we're serving */
	u64			*map;		/* local buffer */
	size_t			map_len;	/* length of a buffer */
	int			fd;		/* file to read PMs from */
} pmc_t;

#define PMC_INIT (pmc_t){ }

extern int pmc_init(pmc_t *pmc, pid_t pid, struct list_head *vma_head, size_t size);
extern u64 *pmc_get_map(pmc_t *pmc, struct vma_area *vma);
extern void pmc_fini(pmc_t *pmc);

#endif /* __CR_PAGEMAP_H__ */
