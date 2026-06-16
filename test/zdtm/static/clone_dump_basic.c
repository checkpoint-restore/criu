#include <sys/mman.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "zdtmtst.h"
#include "clone_dump_util.h"

const char *test_doc = "--clone-dump skeleton + pipe sanity: verifies every page "
		       "in a static anon-private mapping survives restore with "
		       "exact content. Each page has a unique marker derived from "
		       "its index - detects off-by-one, lost pages, and corruption.";
const char *test_author = "Asaf Porat Stoler <asafpor@gmail.com>";


#define NR_PAGES	1024
#define DRAIN_TIMEOUT	10000	/* ms */

/*
 * Compute expected marker for page i. Uses full byte range and varies
 * across the page to catch partial-page corruption.
 */
static inline unsigned char page_marker(int page_idx, int byte_offset)
{
	return (unsigned char)((page_idx + byte_offset) & 0xff);
}

int main(int argc, char **argv)
{
	unsigned char *mem;
	unsigned long sz = NR_PAGES * PAGE_SIZE;
	int i, j;
	int errors = 0;
	int first_error_page = -1, last_error_page = -1;

	test_init(argc, argv);

	mem = mmap(NULL, sz, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (mem == MAP_FAILED) {
		pr_perror("mmap");
		return 1;
	}

	/*
	 * Fill each page with a pattern that varies both by page and by offset.
	 * This catches:
	 * - Wrong page delivered (marker mismatch)
	 * - Partial page (offset mismatch within page)
	 * - Off-by-one errors (adjacent pages differ)
	 */
	for (i = 0; i < NR_PAGES; i++) {
		unsigned char *page = mem + i * PAGE_SIZE;
		for (j = 0; j < PAGE_SIZE; j++)
			page[j] = page_marker(i, j);
	}

	test_daemon();
	test_waitsig();

	if (clone_wait_for_drain(mem, sz, DRAIN_TIMEOUT) < 0) {
		fail("lazy-pages drain did not complete within %d ms", DRAIN_TIMEOUT);
		return 1;
	}

	/*
	 * Verify every byte of every page. Track first and last error pages
	 * to help diagnose off-by-one or range issues.
	 */
	for (i = 0; i < NR_PAGES; i++) {
		unsigned char *page = mem + i * PAGE_SIZE;
		int page_ok = 1;

		for (j = 0; j < PAGE_SIZE; j++) {
			unsigned char expected = page_marker(i, j);
			if (page[j] != expected) {
				if (errors < 8)
					test_msg("page %d offset %d: got 0x%02x expected 0x%02x\n",
						 i, j, page[j], expected);
				page_ok = 0;
				break;
			}
		}

		if (!page_ok) {
			if (first_error_page < 0)
				first_error_page = i;
			last_error_page = i;
			errors++;
		}
	}

	if (errors) {
		test_msg("SUMMARY: %d/%d pages corrupted, "
			 "first_error=%d last_error=%d\n",
			 errors, NR_PAGES, first_error_page, last_error_page);
		fail("page corruption detected after --clone-dump restore");
		return 1;
	}

	test_msg("OK: all %d pages verified with per-byte pattern\n", NR_PAGES);
	pass();
	return 0;
}
