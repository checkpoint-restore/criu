#ifndef __CLONE_DUMP_UTIL_H__
#define __CLONE_DUMP_UTIL_H__

#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "zdtmtst.h"

/*
 * Wait for every page of [addr, addr+len) to become resident in the
 * caller's address space. For a lazy-pages-backed restore this gates
 * subsequent content verification on the lazy-pages daemon having
 * finished draining its buffer via UFFDIO_COPY.
 *
 * Without this gate, pages the daemon has not yet COPY-ed would fault
 * on first read and be served on demand. The verify loop would then
 * still see the right bytes, masking bugs where the daemon drops pages
 * from its buffer mid-drain, exits early, or loses the race described
 * in criu/clone/DRAIN_RACE_BUG.md.
 *
 * mincore() returns bit 0 set per page if the page is present in the
 * process's page table; for UFFD-missing pages the bit is 0 until the
 * daemon performs UFFDIO_COPY. mincore does NOT trigger the fault, so
 * it's a pure observation.
 *
 * Returns 0 when all pages are resident, -1 on timeout or error.
 */
static inline int clone_wait_for_drain(const void *addr, size_t len,
				     unsigned int timeout_ms)
{
	size_t nr_pages = len / PAGE_SIZE;
	unsigned char *vec;
	unsigned int waited = 0;
	const unsigned int step = 50;

	vec = malloc(nr_pages);
	if (!vec) {
		pr_perror("malloc vec");
		return -1;
	}

	while (1) {
		size_t resident = 0, i;

		if (mincore((void *)addr, len, (void *)vec) < 0) {
			pr_perror("mincore");
			free(vec);
			return -1;
		}
		for (i = 0; i < nr_pages; i++)
			if (vec[i] & 1)
				resident++;
		if (resident == nr_pages) {
			test_msg("drain complete: %zu/%zu pages resident (waited %u ms)\n",
				 resident, nr_pages, waited);
			free(vec);
			return 0;
		}
		if (waited >= timeout_ms) {
			test_msg("drain timeout: %zu/%zu pages resident after %u ms\n",
				 resident, nr_pages, timeout_ms);
			free(vec);
			return -1;
		}
		usleep(step * 1000);
		waited += step;
	}
}

#endif /* __CLONE_DUMP_UTIL_H__ */
