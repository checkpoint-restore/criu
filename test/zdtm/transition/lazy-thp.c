#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <linux/limits.h>
#include "zdtmtst.h"

#define N_PAGES 1024

const char *test_doc = "Test interaction between THP and lazy-pages";

/* The test is based on example by Adrian Reber <areber@redhat.com> */
const char *test_author = "Mike Rapoport <rppt@linux.vnet.ibm.com>";

int main(int argc, char **argv)
{
	char *mem, *org, *m;
	int count;

	test_init(argc, argv);

	/* we presume that malloc returns not page aligned address */
	mem = malloc(PAGE_SIZE * N_PAGES);
	org = malloc(PAGE_SIZE);
	if (!mem || !org) {
		fail("malloc failed");
		exit(1);
	}

	memset(mem, 0x42, PAGE_SIZE * N_PAGES);
	memset(org, 0x42, PAGE_SIZE);

	test_daemon();
	while (test_go()) {
		for (count = 0; count < N_PAGES; count += 2) {
			m = mem + (count * PAGE_SIZE) + 128;
			*m = count;
		}

		for (count = 0; count < N_PAGES; count++) {
			m = mem + (count * PAGE_SIZE);
			org[128] = (count % 2 == 0) ? count : 0x42;

			if (memcmp(org, m, PAGE_SIZE)) {
				fail("memory corruption");
				return 1;
			}
		}

		sleep(1);
	}

	pass();
	free(org);
	free(mem);
	return 0;
}
