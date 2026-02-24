#include <stdbool.h>
#include "types.h"
#include "page.h"
#include "mem.h"
#include "atomic-bitmap.h"
#include "criu-log.h"

void cow_set_bitmap(unsigned long vaddr)
{
	unsigned long page_addr = vaddr & ~(PAGE_SIZE - 1);
	struct lazy_vma_entry *lve;
	unsigned long page_idx;

	lve = find_lazy_vma_by_addr(page_addr);
	if (!lve || !lve->cow_bitmap) {
		pr_warn("cow_set_bitmap: addr 0x%lx not in any tracked VMA\n",
			page_addr);
		return;
	}

	page_idx = (page_addr - lve->start) / PAGE_SIZE;

	atomic_bitmap_set(lve->cow_bitmap, page_idx);
}

void cow_clear_bitmap(unsigned long vaddr)
{
	unsigned long page_addr = vaddr & ~(PAGE_SIZE - 1);
	struct lazy_vma_entry *lve;
	unsigned long page_idx;

	lve = find_lazy_vma_by_addr(page_addr);
	if (!lve || !lve->cow_bitmap)
		return;

	page_idx = (page_addr - lve->start) / PAGE_SIZE;

	atomic_bitmap_clear(lve->cow_bitmap, page_idx);
}

bool cow_test_bitmap(unsigned long vaddr)
{
	unsigned long page_addr = vaddr & ~(PAGE_SIZE - 1);
	struct lazy_vma_entry *lve;
	unsigned long page_idx;

	lve = find_lazy_vma_by_addr(page_addr);
	if (!lve || !lve->cow_bitmap)
		return false;

	page_idx = (page_addr - lve->start) / PAGE_SIZE;

	return atomic_bitmap_test(lve->cow_bitmap, page_idx);
}
