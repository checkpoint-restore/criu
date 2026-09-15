#include <stdint.h>
#include <string.h>
#include <sys/mman.h>

#include "zdtmtst.h"

const char *test_doc = "External-memory restore falls back to local image files";
const char *test_author = "Dan Feigin <dfeigin@nvidia.com>";

#define MEMORY_SIZE (64 * 1024)
#define MEMORY_BYTE 0x5a

static int check_memory(const uint8_t *memory)
{
	size_t i;

	for (i = 0; i < MEMORY_SIZE; i++)
		if (memory[i] != MEMORY_BYTE)
			return -1;
	return 0;
}

int main(int argc, char **argv)
{
	uint8_t *memory;

	test_init(argc, argv);

	memory = mmap(NULL, MEMORY_SIZE, PROT_READ | PROT_WRITE,
		      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (memory == MAP_FAILED) {
		pr_perror("private mmap");
		return 1;
	}

	memset(memory, MEMORY_BYTE, MEMORY_SIZE);

	test_daemon();
	test_waitsig();

	if (check_memory(memory)) {
		fail("external-memory content changed");
		return 1;
	}

	pass();
	return 0;
}
