#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <sys/mman.h>
#include <setjmp.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "zdtmtst.h"

const char *test_doc	= "Create a bunch of small VMAs and test they survive transferring\n";
const char *test_author	= "Cyrill Gorcunov <gorcunov@openvz.org>";

#define NR_MAPS		4096

#define NR_MAPS_1	(NR_MAPS + 0)
#define NR_MAPS_2	(NR_MAPS + 1)

#define MAPS_SIZE_1	(140 << 10)
#define MAPS_SIZE_2	(8192)

int main(int argc, char *argv[])
{
	void *map[NR_MAPS + 2] = { }, *addr;
	size_t i, summary;

	test_init(argc, argv);

	summary = NR_MAPS * 2 * 4096 + MAPS_SIZE_1 + MAPS_SIZE_2 + (1 << 20);

	addr = mmap(NULL, summary, PROT_NONE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	if (addr == MAP_FAILED) {
		err("Can't mmap");
		return 1;
	}
	munmap(addr, summary);

	for (i = 0; i < NR_MAPS; i++) {
		map[i] = mmap(i > 0 ? map[i - 1] + 8192 : addr, 4096, PROT_READ | PROT_WRITE,
			      MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
		if (map[i] == MAP_FAILED) {
			err("Can't mmap");
			return 1;
		} else {
			/* Dirtify it */
			int *v = (void *)map[i];
			*v = i;
		}
	}

	map[NR_MAPS_1] = mmap(map[NR_MAPS_1 - 1] + 8192, MAPS_SIZE_1, PROT_READ | PROT_WRITE | PROT_EXEC,
			      MAP_ANONYMOUS | MAP_PRIVATE | MAP_GROWSDOWN, -1, 0);
	if (map[NR_MAPS_1] == MAP_FAILED) {
		err("Can't mmap");
		return 1;
	} else {
		/* Dirtify it */
		int *v = (void *)map[NR_MAPS_1];
		*v = i;
		test_msg("map-1: %p %p\n", map[NR_MAPS_1], map[NR_MAPS_1] + MAPS_SIZE_1);
	}

	map[NR_MAPS_2] = mmap(map[NR_MAPS_1] + MAPS_SIZE_1, MAPS_SIZE_2, PROT_READ | PROT_WRITE,
			      MAP_ANONYMOUS | MAP_PRIVATE | MAP_GROWSDOWN, -1, 0);
	if (map[NR_MAPS_2] == MAP_FAILED) {
		err("Can't mmap");
		return 1;
	} else {
		/* Dirtify it */
		int *v = (void *)map[NR_MAPS_2];
		*v = i;
		test_msg("map-2: %p %p\n", map[NR_MAPS_2], map[NR_MAPS_2] + MAPS_SIZE_2);
	}

	test_daemon();
	test_waitsig();

	for (i = 0; i < NR_MAPS; i++) {
		int *v = (void *)map[i];

		if (*v != i) {
			fail("Data corrupted at page %lu", (unsigned long)i);
			return 1;
		}
	}

	pass();
	return 0;
}
