#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include "zdtmtst.h"
#include "get_smaps_bits.h"

#ifndef MADV_HUGEPAGE
#define MADV_HUGEPAGE 14
#endif

#ifndef MADV_NOHUGEPAGE
#define MADV_NOHUGEPAGE 15
#endif

const char *test_doc = "Check that restored memory is backed by the page size its THP advice asks for";
const char *test_author = "Partha P.G. <yes.par781@gmail.com>";

/* Larger PMD sizes (e.g. 512M with 64K pages) make the test too heavy */
#define MAX_PMD_SIZE (32UL << 20)

static unsigned long pmd_size(void)
{
	unsigned long size = 0;
	FILE *f;

	f = fopen("/sys/kernel/mm/transparent_hugepage/hpage_pmd_size", "r");
	if (!f)
		return 0;
	if (fscanf(f, "%lu", &size) != 1)
		size = 0;
	fclose(f);
	return size;
}

/* Map an area aligned to @align, so whole PMDs fit inside it */
static void *map_area(unsigned long size, unsigned long align, int advice)
{
	unsigned long head, tail;
	char *raw, *area;

	raw = mmap(NULL, size + align, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (raw == MAP_FAILED) {
		pr_perror("mmap failed");
		return NULL;
	}

	area = (char *)(((unsigned long)raw + align - 1) & ~(align - 1));
	head = area - raw;
	tail = align - head;
	if (head && munmap(raw, head)) {
		pr_perror("munmap head failed");
		return NULL;
	}
	if (tail && munmap(area + size, tail)) {
		pr_perror("munmap tail failed");
		return NULL;
	}

	if (madvise(area, size, advice)) {
		pr_perror("madvise(%d) failed", advice);
		return NULL;
	}

	return area;
}

/* Return AnonHugePages in kB for the VMA holding @addr, or -1 on error */
static long anon_huge_kb(void *addr)
{
	unsigned long start, end, a = (unsigned long)addr;
	char line[512];
	bool in_vma = false;
	long kb = -1;
	FILE *f;

	f = fopen("/proc/self/smaps", "r");
	if (!f) {
		pr_perror("Can't open smaps");
		return -1;
	}

	while (fgets(line, sizeof(line), f)) {
		if (sscanf(line, "%lx-%lx ", &start, &end) == 2) {
			in_vma = a >= start && a < end;
			continue;
		}
		if (in_vma && sscanf(line, "AnonHugePages: %ld kB", &kb) == 1)
			break;
	}

	fclose(f);
	if (kb < 0)
		pr_err("No AnonHugePages for %p\n", addr);
	return kb;
}

static int check_madv(void *addr, unsigned long want)
{
	unsigned long flags = 0, madv = 0;

	if (get_smaps_bits((unsigned long)addr, &flags, &madv))
		return -1;
	if (!(madv & want)) {
		fail("Advice %lx lost on %p (madv %lx)", want, addr, madv);
		return -1;
	}
	return 0;
}

int main(int argc, char **argv)
{
	unsigned long pmd, size;
	uint32_t crc_huge = ~0, crc_base = ~0;
	long huge_before, huge_after, base_after;
	uint8_t *huge, *base;

	test_init(argc, argv);

	pmd = pmd_size();
	if (pmd > MAX_PMD_SIZE)
		pmd = 0;
	size = pmd ? 2 * pmd : (4UL << 20);

	huge = map_area(size, pmd ?: PAGE_SIZE, MADV_HUGEPAGE);
	base = map_area(size, pmd ?: PAGE_SIZE, MADV_NOHUGEPAGE);
	if (!huge || !base)
		return 1;

	datagen(huge, size, &crc_huge);
	datagen(base, size, &crc_base);

	/*
	 * Huge pages may be unavailable here, e.g. with THP set to "never" or
	 * when memory is too fragmented. Only expect them after restore if the
	 * kernel gave them before the dump.
	 */
	huge_before = anon_huge_kb(huge);
	if (huge_before < 0 || anon_huge_kb(base) < 0)
		return 1;
	test_msg("AnonHugePages before dump: %ld kB\n", huge_before);

	test_daemon();
	test_waitsig();

	crc_huge = ~0;
	crc_base = ~0;
	if (datachk(huge, size, &crc_huge) || datachk(base, size, &crc_base)) {
		fail("Memory contents changed");
		return 1;
	}

	if (check_madv(huge, 1UL << MADV_HUGEPAGE) || check_madv(base, 1UL << MADV_NOHUGEPAGE))
		return 1;

	huge_after = anon_huge_kb(huge);
	base_after = anon_huge_kb(base);
	if (huge_after < 0 || base_after < 0)
		return 1;
	test_msg("AnonHugePages after restore: %ld kB\n", huge_after);

	if (base_after) {
		fail("MADV_NOHUGEPAGE area restored with %ld kB of huge pages", base_after);
		return 1;
	}

	if (huge_before && !huge_after) {
		fail("MADV_HUGEPAGE area restored without huge pages (%ld kB before dump)", huge_before);
		return 1;
	}

	pass();
	return 0;
}
