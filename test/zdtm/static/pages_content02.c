#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <sys/stat.h>

#include "zdtmtst.h"

const char *test_doc = "Check page integrity across different mapping types";
const char *test_author = "Radostin Stoyanov <rstoyanov@fedoraproject.org>";

/*
 * Exercise memory page compression with diverse mapping types:
 *
 *   0. MAP_PRIVATE | MAP_ANONYMOUS         (heap-like, most common)
 *   1. MAP_PRIVATE | MAP_ANONYMOUS (zeros) (zero-page detection)
 *   2. MAP_SHARED  | MAP_ANONYMOUS         (shared anon between parent/child)
 *   3. MAP_PRIVATE file-backed             (private file mapping with CoW)
 *   4. MAP_SHARED  file-backed             (shared file mapping)
 *   5. memfd shared mapping                (anonymous shared file)
 *   6. Read-only anonymous mapping         (PROT_READ after write)
 *   7. PROT_NONE guard + data page         (guard page boundary)
 *
 * Each region is filled with datagen() and verified with datachk()
 * after restore. The test forks a child that shares regions 2, 4,
 * and 5, verifying both processes see correct data independently.
 */

char *filename;
TEST_OPTION(filename, string, "file name", 1);

#define NR_PAGES	8
#define REGION_SIZE	(NR_PAGES * PAGE_SIZE)

#define INIT_CRC	(~(uint32_t)0)

struct region {
	const char *name;
	void *addr;
	size_t size;
	uint32_t crc;
	int check;	/* 1 = verify with datachk, 0 = skip */
};

#define NR_REGIONS 8

static int verify_regions(struct region *regions, int n, const char *who)
{
	int i;

	for (i = 0; i < n; i++) {
		uint32_t crc;

		if (!regions[i].check)
			continue;

		crc = regions[i].crc;
		if (datachk(regions[i].addr, regions[i].size, &crc)) {
			fail("%s: data mismatch in region '%s'",
			     who, regions[i].name);
			return -1;
		}
	}
	return 0;
}

int main(int argc, char **argv)
{
	struct region regions[NR_REGIONS];
	int fd = -1, memfd = -1;
	pid_t pid;
	int status;
	int pipe_fds[2];
	char sync_byte;
	ssize_t ret;
	uint32_t crc;
	void *addr;
	int i = 0;

	test_init(argc, argv);

	/* Create a temp file for file-backed mappings */
	fd = open(filename, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) {
		pr_perror("open(%s)", filename);
		return 1;
	}
	if (ftruncate(fd, REGION_SIZE * 2) < 0) {
		pr_perror("ftruncate");
		return 1;
	}

	/*
	 * Region 0: MAP_PRIVATE | MAP_ANONYMOUS (data pages)
	 */
	addr = mmap(NULL, REGION_SIZE, PROT_READ | PROT_WRITE,
		    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (addr == MAP_FAILED) {
		pr_perror("mmap anon private");
		return 1;
	}
	crc = INIT_CRC;
	datagen(addr, REGION_SIZE, &crc);
	regions[i++] = (struct region){
		.name = "anon-private", .addr = addr,
		.size = REGION_SIZE, .crc = INIT_CRC, .check = 1
	};

	/*
	 * Region 1: MAP_PRIVATE | MAP_ANONYMOUS (all zeros)
	 * Tests zero-page detection (compressed_size == 0).
	 * Verified separately (not via datachk).
	 */
	addr = mmap(NULL, REGION_SIZE, PROT_READ | PROT_WRITE,
		    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (addr == MAP_FAILED) {
		pr_perror("mmap anon zero");
		return 1;
	}
	memset(addr, 0, REGION_SIZE);
	regions[i++] = (struct region){
		.name = "anon-zero", .addr = addr,
		.size = REGION_SIZE, .crc = 0, .check = 0
	};

	/*
	 * Region 2: MAP_SHARED | MAP_ANONYMOUS (shared between parent/child)
	 */
	addr = mmap(NULL, REGION_SIZE, PROT_READ | PROT_WRITE,
		    MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (addr == MAP_FAILED) {
		pr_perror("mmap anon shared");
		return 1;
	}
	crc = INIT_CRC + 1;
	datagen(addr, REGION_SIZE, &crc);
	regions[i++] = (struct region){
		.name = "anon-shared", .addr = addr,
		.size = REGION_SIZE, .crc = INIT_CRC + 1, .check = 1
	};

	/*
	 * Region 3: MAP_PRIVATE file-backed (private file CoW)
	 */
	addr = mmap(NULL, REGION_SIZE, PROT_READ | PROT_WRITE,
		    MAP_PRIVATE, fd, 0);
	if (addr == MAP_FAILED) {
		pr_perror("mmap file private");
		return 1;
	}
	crc = INIT_CRC + 2;
	datagen(addr, REGION_SIZE, &crc);
	regions[i++] = (struct region){
		.name = "file-private", .addr = addr,
		.size = REGION_SIZE, .crc = INIT_CRC + 2, .check = 1
	};

	/*
	 * Region 4: MAP_SHARED file-backed (shared between parent/child)
	 */
	addr = mmap(NULL, REGION_SIZE, PROT_READ | PROT_WRITE,
		    MAP_SHARED, fd, REGION_SIZE);
	if (addr == MAP_FAILED) {
		pr_perror("mmap file shared");
		return 1;
	}
	crc = INIT_CRC + 3;
	datagen(addr, REGION_SIZE, &crc);
	if (msync(addr, REGION_SIZE, MS_SYNC) < 0) {
		pr_perror("msync");
		return 1;
	}
	regions[i++] = (struct region){
		.name = "file-shared", .addr = addr,
		.size = REGION_SIZE, .crc = INIT_CRC + 3, .check = 1
	};

	/*
	 * Region 5: memfd shared mapping (anonymous shared file)
	 */
	memfd = syscall(__NR_memfd_create, "compress_test", 0);
	if (memfd < 0) {
		pr_perror("memfd_create");
		return 1;
	}
	if (ftruncate(memfd, REGION_SIZE) < 0) {
		pr_perror("ftruncate memfd");
		return 1;
	}
	addr = mmap(NULL, REGION_SIZE, PROT_READ | PROT_WRITE,
		    MAP_SHARED, memfd, 0);
	if (addr == MAP_FAILED) {
		pr_perror("mmap memfd");
		return 1;
	}
	close(memfd);
	crc = INIT_CRC + 4;
	datagen(addr, REGION_SIZE, &crc);
	regions[i++] = (struct region){
		.name = "memfd-shared", .addr = addr,
		.size = REGION_SIZE, .crc = INIT_CRC + 4, .check = 1
	};

	/*
	 * Region 6: Read-only anonymous mapping
	 */
	addr = mmap(NULL, REGION_SIZE, PROT_READ | PROT_WRITE,
		    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (addr == MAP_FAILED) {
		pr_perror("mmap anon readonly");
		return 1;
	}
	crc = INIT_CRC + 5;
	datagen(addr, REGION_SIZE, &crc);
	if (mprotect(addr, REGION_SIZE, PROT_READ) < 0) {
		pr_perror("mprotect PROT_READ");
		return 1;
	}
	regions[i++] = (struct region){
		.name = "anon-readonly", .addr = addr,
		.size = REGION_SIZE, .crc = INIT_CRC + 5, .check = 1
	};

	/*
	 * Region 7: PROT_NONE guard + data page
	 */
	addr = mmap(NULL, 2 * PAGE_SIZE, PROT_READ | PROT_WRITE,
		    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (addr == MAP_FAILED) {
		pr_perror("mmap guard");
		return 1;
	}
	crc = INIT_CRC + 6;
	datagen((uint8_t *)addr + PAGE_SIZE, PAGE_SIZE, &crc);
	if (mprotect(addr, PAGE_SIZE, PROT_NONE) < 0) {
		pr_perror("mprotect PROT_NONE");
		return 1;
	}
	regions[i++] = (struct region){
		.name = "guard+data", .addr = (char *)addr + PAGE_SIZE,
		.size = PAGE_SIZE, .crc = INIT_CRC + 6, .check = 1
	};

	if (pipe(pipe_fds)) {
		pr_perror("pipe");
		return 1;
	}

	pid = test_fork();
	if (pid < 0) {
		pr_perror("fork");
		return 1;
	}

	if (pid == 0) {
		close(pipe_fds[0]);
		sync_byte = 1;
		if (write(pipe_fds[1], &sync_byte, 1) != 1)
			_exit(1);
		close(pipe_fds[1]);

		test_waitsig();

		if (verify_regions(regions, NR_REGIONS, "child"))
			_exit(1);

		_exit(0);
	}

	close(pipe_fds[1]);
	ret = read(pipe_fds[0], &sync_byte, 1);
	if (ret != 1) {
		if (ret < 0)
			pr_perror("parent: pipe read");
		else
			pr_err("parent: short pipe read: %zd of 1 byte\n", ret);
		goto err;
	}
	close(pipe_fds[0]);
	close(fd);

	test_daemon();
	test_waitsig();

	/* Verify all data regions */
	if (verify_regions(regions, NR_REGIONS, "parent"))
		goto err;

	/* Verify zero region explicitly */
	{
		char *zp = regions[1].addr;
		int j;

		for (j = 0; j < (int)REGION_SIZE; j++) {
			if (zp[j] != 0) {
				fail("parent: zero region byte %d is 0x%02x",
				     j, (unsigned char)zp[j]);
				goto err;
			}
		}
	}

	/* Wake child, reap */
	kill(pid, SIGTERM);
	if (waitpid(pid, &status, 0) != pid) {
		pr_perror("waitpid");
		goto err;
	}
	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
		fail("child exited with status %d", status);
		goto err;
	}

	pass();
	return 0;

err:
	kill(pid, SIGKILL);
	waitpid(pid, NULL, 0);
	return 1;
}
