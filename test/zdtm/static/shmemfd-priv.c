#include <unistd.h>
#include <stdio.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/vfs.h>
#include <fcntl.h>

#include "zdtmtst.h"

const char *test_doc = "Test C/R of shared memory file descriptors";
const char *test_author = "Andrei Vagin <avagin@gmail.com>";

#define err(exitcode, msg, ...)                \
	({                                     \
		pr_perror(msg, ##__VA_ARGS__); \
		exit(exitcode);                \
	})

int main(int argc, char *argv[])
{
	void *addr, *priv_addr, *addr2;
	char path[4096];
	int fd;

	test_init(argc, argv);

	addr = mmap(NULL, 5 * PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_SHARED, -1, 0);
	if (addr == MAP_FAILED) {
		pr_perror("mmap");
		return 1;
	}

	*(int *)addr = 1;
	*(int *)(addr + PAGE_SIZE) = 11;
	*(int *)(addr + 2 * PAGE_SIZE) = 111;

	snprintf(path, sizeof(path), "/proc/self/map_files/%lx-%lx", (long)addr, (long)addr + 5 * PAGE_SIZE);
	fd = open(path, O_RDWR | O_LARGEFILE);
	if (fd < 0)
		err(1, "Can't open %s", path);

	priv_addr = mmap(NULL, 5 * PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_FILE | MAP_PRIVATE, fd, PAGE_SIZE);
	if (priv_addr == MAP_FAILED) {
		pr_perror("mmap");
		return 1;
	}

	addr2 = mmap(NULL, 5 * PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_FILE | MAP_SHARED, fd, 2 * PAGE_SIZE);
	if (addr2 == MAP_FAILED) {
		pr_perror("mmap");
		return 1;
	}

	*(int *)(priv_addr + PAGE_SIZE) = 22;

	test_daemon();
	test_waitsig();

	if (*(int *)(priv_addr + PAGE_SIZE) != 22) {
		fail("the second page of the private mapping is corrupted");
		return 1;
	}
	if (*(int *)(priv_addr) != 11) {
		fail("the first page of the private mapping is corrupted");
		return 1;
	}
	if (*(int *)(addr2) != 111) {
		fail("the first page of the second shared mapping is corrupted");
		return 1;
	}
	*(int *)(addr2) = 333;
	if (*(int *)(addr + 2 * PAGE_SIZE) != 333) {
		fail("the first page of the second shared mapping isn't shared");
		return 1;
	}
	*(int *)(addr + 3 * PAGE_SIZE) = 444;
	if (*(int *)(priv_addr + 2 * PAGE_SIZE) != 444) {
		fail("the third page of the private mapping is corrupted");
		return 1;
	}

	pass();

	return 0;
}
