#ifndef __CR_COW_BITMAP_H__
#define __CR_COW_BITMAP_H__

#include <stdbool.h>

/* COW bitmap operations for tracking write-faulted pages */
extern void cow_set_bitmap(unsigned long vaddr);
extern void cow_clear_bitmap(unsigned long vaddr);
extern bool cow_test_bitmap(unsigned long vaddr);

#endif /* __CR_COW_BITMAP_H__ */
