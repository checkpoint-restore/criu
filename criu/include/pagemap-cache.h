#ifndef __CR_PAGEMAP_H__
#define __CR_PAGEMAP_H__

#include <stdbool.h>
#include <sys/types.h>
#include "int.h"

#include "common/list.h"
#include "pagemap_scan.h"

struct vma_area;

#define PAGEMAP_PFN_OFF(addr) (PAGE_PFN(addr) * sizeof(u64))

typedef struct {
	pid_t pid;			  /* which process it belongs */
	unsigned long start;		  /* start of area */
	unsigned long end;		  /* end of area */
	const struct list_head *vma_head; /* list head of VMAs we're serving */
	int fd;				  /* file to read PMs from */

	u64 *map;			  /* local buffer */
	size_t map_len;			  /* length of a buffer */

	struct page_region *regs; /* buffer for the PAGEMAP_SCAN ioctl */
	size_t regs_len;	  /* actual length of regs */
	size_t regs_max_len;	  /* maximum length of regs */
	size_t regs_idx;	  /* current index in the regs array */
} pmc_t;

#define PMC_INIT \
	(pmc_t)  \
	{        \
	}

extern int pmc_init(pmc_t *pmc, pid_t pid, const struct list_head *vma_head, size_t size);
extern int pmc_get_map(pmc_t *pmc, const struct vma_area *vma);
extern void pmc_fini(pmc_t *pmc);
extern int pmc_fill(pmc_t *pmc, u64 start, u64 end);

#endif /* __CR_PAGEMAP_H__ */
