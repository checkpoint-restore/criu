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

const char *test_doc = "Test uffd events";
const char *test_author = "Mike Rapoport <rppt@linux.vnet.ibm.com>";

#define NR_MAPS	 5
#define MAP_SIZE (1 << 20)

static void *map[NR_MAPS];

static int create_mappings(void)
{
	uint32_t crc;
	int i;

	for (i = 0; i < NR_MAPS; i++) {
		map[i] = mmap(NULL, MAP_SIZE, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
		if (map[i] == MAP_FAILED) {
			fail("mmap failed");
			return 1;
		}

		crc = i;
		datagen(map[i], MAP_SIZE, &crc);
	}

	return 0;
}

static int verify_zeroes(void *m)
{
	int i;

	for (i = 0; i < MAP_SIZE; i += PAGE_SIZE) {
		char *p = m + i;
		if (*p != 0)
			return 1;
	}

	return 0;
}

static int check_madv_dn(int idx)
{
	void *m = map[idx];

	if (madvise(m, MAP_SIZE, MADV_DONTNEED)) {
		fail("madvise failed");
		return 1;
	}

	if (verify_zeroes(m)) {
		fail("not zero");
		return 1;
	}

	return 0;
}

static int check_mremap_grow(int idx)
{
	void *m = map[idx];
	uint32_t crc = idx;

	m = mremap(m, MAP_SIZE, MAP_SIZE * 2, MREMAP_MAYMOVE);
	if (m == MAP_FAILED) {
		fail("mremap failed");
		return 1;
	}

	if (datachk(m, MAP_SIZE, &crc)) {
		fail("Mem corrupted");
		return 1;
	}

	/* the new part of the mapping should be filled with zeroes */
	m += MAP_SIZE;
	if (verify_zeroes(m)) {
		fail("not zeroes");
		return 1;
	}

	return 0;
}

static int check_swapped_mappings(int idx)
{
	uint32_t crc = idx;
	void *m1 = map[idx];
	void *m2 = map[idx + 1];
	void *p = map[0];

	p = mremap(m1, MAP_SIZE, MAP_SIZE, MREMAP_MAYMOVE | MREMAP_FIXED, p);
	if (p == MAP_FAILED) {
		fail("mremap failed");
		return 1;
	}

	m1 = mremap(m2, MAP_SIZE, MAP_SIZE, MREMAP_MAYMOVE | MREMAP_FIXED, m1);
	if (m1 == MAP_FAILED) {
		fail("mremap failed");
		return 1;
	}

	m2 = mremap(p, MAP_SIZE, MAP_SIZE, MREMAP_MAYMOVE | MREMAP_FIXED, m2);
	if (m2 == MAP_FAILED) {
		fail("mremap failed");
		return 1;
	}

	if (datachk(m2, MAP_SIZE, &crc)) {
		fail("Mem corrupted");
		return 1;
	}

	crc = idx + 1;
	if (datachk(m1, MAP_SIZE, &crc)) {
		fail("Mem corrupted");
		return 1;
	}

	return 0;
}

int main(int argc, char **argv)
{
	uint32_t crc;
	int pid;

	test_init(argc, argv);

	if (create_mappings())
		return -1;

	test_daemon();
	test_waitsig();

	/* run some page faults */
	crc = 0;
	if (datachk(map[0], MAP_SIZE, &crc)) {
		fail("Mem corrupted");
		return 1;
	}

	pid = fork();
	if (pid < 0) {
		fail("Can't fork");
		return 1;
	}

	/* check madvise(MADV_DONTNEED) */
	if (check_madv_dn(1))
		return 1;

	/* check growing mremap */
	if (check_mremap_grow(2))
		return 1;

	/* check swapped mappings */
	if (check_swapped_mappings(3))
		return 1;

	if (pid) {
		int status;

		waitpid(-1, &status, 0);
		if (status) {
			fail("child failed");
			return status;
		}
	}

	pass();
	return 0;
}
