#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "zdtmtst.h"

const char *test_doc = "Check the --skip-zero-pages flag";
const char *test_author = "Volker Simonis <volker.simonis@gmail.com>";

#define PME_PFRAME_MASK ((1ULL << 55) - 1)
uint64_t zero_page_pfn;
int page_size;
int pagemap;

static uint64_t vaddr_to_pfn(unsigned long vaddr)
{
	uint64_t pfn;
	off_t off = (vaddr / page_size) * sizeof(uint64_t);
	if (pread(pagemap, &pfn, sizeof(pfn), off) != sizeof(pfn)) {
		pr_perror("Can't read pme");
		exit(1);
	} else {
		return (pfn & PME_PFRAME_MASK);
	}
}

static void init_zero_page_pfn(void)
{
	void *addr;
	if ((pagemap = open("/proc/self/pagemap", O_RDONLY)) == -1) {
		pr_perror("Can't open /proc/self/pagemap");
		exit(1);
	}
	if ((addr = mmap(NULL, page_size, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0)) == MAP_FAILED) {
		pr_perror("Unable to map zero page");
		exit(1);
	}
	if (*((int *)addr) != 0) {
		pr_perror("Newly mapped page must be zero");
		exit(1);
	}
	zero_page_pfn = vaddr_to_pfn((unsigned long)addr);
	munmap(addr, page_size);

	if (zero_page_pfn == 0) {
		pr_err("zero_page_pfn is invalid.\n");
		exit(1);
	}
	fprintf(stderr, "zero_page_pfn = %" PRIu64 "\n", zero_page_pfn);
}

static int pages_in_mem(char *addr, int nr_of_pages)
{
	int counter = 0;
	unsigned char pages[nr_of_pages];
	if (mincore(addr, page_size * nr_of_pages, pages) == -1) {
		pr_perror("Can't call mincore");
		exit(1);
	}
	for (int i = 0; i < nr_of_pages; i++) {
		if ((pages[i] & 0x1)) {
			counter++;
		}
	}
	return counter;
}

static int zero_pages(char *addr, int nr_of_pages)
{
	int counter = 0;
	for (int i = 0; i < nr_of_pages; i++, addr += page_size) {
		if (vaddr_to_pfn((unsigned long)addr) == zero_page_pfn) {
			counter++;
		}
	}
	return counter;
}

int main(int argc, char **argv)
{
	char *addr;
	int nr_of_pages = 64;

	test_init(argc, argv);

	page_size = sysconf(_SC_PAGESIZE);

	init_zero_page_pfn();

	addr = (char *)mmap(NULL, page_size * nr_of_pages, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (addr == MAP_FAILED) {
		pr_perror("Can't mmap %d bytes", page_size * nr_of_pages);
		exit(1);
	}
	/* Check that pages are not in memory yet */
	if (pages_in_mem(addr, nr_of_pages) != 0) {
		pr_err("Pages shouldn't be in memory yet.\n");
		exit(1);
	}
	for (int i = 0; i < nr_of_pages; i++) {
		/* Read pages to bring them into memory */
		if (addr[i * page_size] != 0) {
			pr_err("All pages should have zero content.\n");
			exit(1);
		}
	}
	/* Check that all pages reference the zero page */
	if (zero_pages(addr, nr_of_pages) != nr_of_pages) {
		pr_err("All pages should reference the zero page.\n");
		exit(1);
	}
	for (int i = 0; i < nr_of_pages; i++) {
		/* Write pages to COW them */
		addr[i * page_size] = 0;
	}
	/* Check that all pages are mapped to distinct physical pages */
	if (pages_in_mem(addr, nr_of_pages) != nr_of_pages) {
		pr_err("All pages should be in memory.\n");
		exit(1);
	}

	test_daemon();
	test_waitsig();

	/* Check that pages are not in memory yet */
	if (pages_in_mem(addr, nr_of_pages) != 0) {
		fail("Pages shouldn't be in memory yet");
		goto out;
	}
	for (int i = 0; i < nr_of_pages; i++) {
		/* Read pages to bring them into memory */
		if (addr[i * page_size] != 0) {
			fail("All pages should have zero content");
		}
	}
	/* Check that all pages reference the zero page */
	if (zero_pages(addr, nr_of_pages) != nr_of_pages) {
		fail("All pages should reference the zero page");
		goto out;
	}
	for (int i = 0; i < nr_of_pages; i++) {
		/* Write pages to COW them */
		addr[i * page_size] = 0;
	}
	/* Check that all pages are mapped to distinct physical pages */
	if (pages_in_mem(addr, nr_of_pages) != nr_of_pages) {
		fail("All pages should be in memory");
		goto out;
	}

	pass();
out:
	return 0;
}
