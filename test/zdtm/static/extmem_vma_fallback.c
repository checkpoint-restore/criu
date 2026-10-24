#include <linux/memfd.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "zdtmtst.h"

const char *test_doc = "External-memory restore falls back for unsupported private VMAs";
const char *test_author = "Dan Feigin <dfeigin@nvidia.com>";

#define MEMORY_SIZE  (64 * 1024)
#define PRIVATE_BYTE 0x5a
#define SHARED_BYTE  0x3c

static int create_memfd(const char *name)
{
	return syscall(SYS_memfd_create, name, MFD_ALLOW_SEALING);
}

static int check_memory(const void *address, uint8_t byte)
{
	const uint8_t *memory = address;
	size_t i;

	for (i = 0; i < MEMORY_SIZE; i++)
		if (memory[i] != byte)
			return -1;
	return 0;
}

int main(int argc, char **argv)
{
	void *private, *shared;
	int fd;

	test_init(argc, argv);

	private = mmap(NULL, MEMORY_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (private == MAP_FAILED) {
		pr_perror("private mmap");
		return 1;
	}

	fd = create_memfd("zdtm-extmem-shared");
	if (fd < 0 || ftruncate(fd, MEMORY_SIZE) < 0) {
		pr_perror("shared memfd");
		return 1;
	}
	shared = mmap(NULL, MEMORY_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (shared == MAP_FAILED) {
		pr_perror("shared mmap");
		return 1;
	}

	memset(private, PRIVATE_BYTE, MEMORY_SIZE);
	memset(shared, SHARED_BYTE, MEMORY_SIZE);

	test_daemon();
	test_waitsig();

	if (check_memory(private, PRIVATE_BYTE) || check_memory(shared, SHARED_BYTE)) {
		fail("external-memory content changed");
		return 1;
	}

	pass();
	return 0;
}
