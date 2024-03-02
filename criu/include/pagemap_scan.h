#ifndef __CR_PAGEMAP_SCAN_H__
#define __CR_PAGEMAP_SCAN_H__

#ifndef PAGEMAP_SCAN
#include <sys/types.h>
#include "int.h"

/* Bitmasks provided in pm_scan_args masks and reported in page_region.categories. */
#define PAGE_IS_WPALLOWED  (1 << 0)
#define PAGE_IS_WRITTEN	   (1 << 1)
#define PAGE_IS_FILE	   (1 << 2)
#define PAGE_IS_PRESENT	   (1 << 3)
#define PAGE_IS_SWAPPED	   (1 << 4)
#define PAGE_IS_PFNZERO	   (1 << 5)
#define PAGE_IS_HUGE	   (1 << 6)
#define PAGE_IS_SOFT_DIRTY (1 << 7)

/*
 * struct page_region - Page region with flags
 * @start:      Start of the region
 * @end:        End of the region (exclusive)
 * @categories: PAGE_IS_* category bitmask for the region
 */
struct page_region {
	u64 start;
	u64 end;
	u64 categories;
};

#define PAGEMAP_SCAN _IOWR('f', 16, struct pm_scan_arg)

/* Flags for PAGEMAP_SCAN ioctl */
#define PM_SCAN_WP_MATCHING   (1 << 0) /* Write protect the pages matched. */
#define PM_SCAN_CHECK_WPASYNC (1 << 1) /* Abort the scan when a non-WP-enabled page is found. */

/*
 * struct pm_scan_arg - Pagemap ioctl argument
 * @size:               Size of the structure
 * @flags:              Flags for the IOCTL
 * @start:              Starting address of the region
 * @end:                Ending address of the region
 * @walk_end            Address where the scan stopped (written by kernel).
 *                      walk_end == end (address tags cleared) informs that the scan completed on entire range.
 * @vec:                Address of page_region struct array for output
 * @vec_len:            Length of the page_region struct array
 * @max_pages:          Optional limit for number of returned pages (0 = disabled)
 * @category_inverted:  PAGE_IS_* categories which values match if 0 instead of 1
 * @category_mask:      Skip pages for which any category doesn't match
 * @category_anyof_mask: Skip pages for which no category matches
 * @return_mask:        PAGE_IS_* categories that are to be reported in `page_region`s returned
 */
struct pm_scan_arg {
	u64 size;
	u64 flags;
	u64 start;
	u64 end;
	u64 walk_end;
	u64 vec;
	u64 vec_len;
	u64 max_pages;
	u64 category_inverted;
	u64 category_mask;
	u64 category_anyof_mask;
	u64 return_mask;
};
#endif /* PAGEMAP_SCAN */

#endif /* __CR_PAGEMAP_SCAN_H__ */
