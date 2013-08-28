#include <fcntl.h>
#include <sys/mman.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <sys/wait.h>
#include <linux/limits.h>
#include <sys/user.h>
#include <stdlib.h>

#include "zdtmtst.h"

const char *test_doc	= "Check that cow memory are restored";
const char *test_author	= "Andrey Vagin <avagin@parallels.com";

char *filename;
TEST_OPTION(filename, string, "file name", 1);

struct test_case {
	union {
		struct {
			uint8_t b_f_write:1;		/* before fork */
			uint8_t b_f_read:1;
			uint8_t a_f_write_child:1;	/* after fork */
			uint8_t a_f_write_parent:1;
			uint8_t a_f_read_child:1;
			uint8_t a_f_read_parent:1;
#define			TEST_CASES (2 << 6)
		};
		uint8_t num;
	};

	uint32_t crc_parent;
	uint32_t crc_child;

};

struct test_cases {
	struct test_case tc[TEST_CASES];
	void *addr;
	int (*init)(struct test_cases *tcs);
};

static int init_cow(struct test_cases *);
static int init_cow_gd(struct test_cases *tcs);
static int init_sep(struct test_cases *);
static int init_file(struct test_cases *);

static pid_t child_pid;

#define EXECUTE_ACTION(func) ({		\
	int __ret = 0;			\
	__ret += func(&sep_tcs);	\
	__ret += func(&cow_tcs);	\
	__ret += func(&cow_gd_tcs);	\
	__ret += func(&file_tcs);	\
	__ret;				\
})

struct test_cases cow_tcs = {.init = init_cow},
		  sep_tcs = {.init = init_sep},
		  file_tcs = {.init = init_file},
		  cow_gd_tcs = {.init = init_cow_gd};

uint32_t zero_crc = ~1;

static int is_cow(void *addr, pid_t p1, pid_t p2)
{
	char buf[PATH_MAX];
	unsigned long pfn = (unsigned long) addr / PAGE_SIZE;
	uint64_t map1, map2;
	int fd1, fd2, ret, i;

	snprintf(buf, sizeof(buf), "/proc/%d/pagemap", p1);
	fd1 = open(buf, O_RDONLY);
	if (fd1 < 0) {
		err("Unable to open file %s", buf);
		return -1;
	}

	snprintf(buf, sizeof(buf), "/proc/%d/pagemap", p2);
	fd2 = open(buf, O_RDONLY);
	if (fd1 < 0) {
		err("Unable to open file %s", buf);
		return -1;
	}

	/*
	 * A page can be swapped or unswapped,
	 * so we should do several iterations.
	 */
	for (i = 0; i < 10; i++) {
		lseek(fd1, pfn * sizeof(map1), SEEK_SET);
		lseek(fd2, pfn * sizeof(map2), SEEK_SET);

		ret = read(fd1, &map1, sizeof(map1));
		if (ret != sizeof(map1)) {
			err("Unable to read data");
			return -1;
		}

		ret = read(fd2, &map2, sizeof(map2));
		if (ret != sizeof(map2)) {
			err("Unable to read data");
			return -1;
		}

		if (map1 == map2)
			break;
	}

	close(fd1);
	close(fd2);

	return map1 == map2;
}

static int child_prep(struct test_cases *test_cases)
{
	int i;
	uint8_t *addr = test_cases->addr;

	for (i = 0; i < TEST_CASES; i++) {
		struct test_case *tc = test_cases->tc + i;
		if (tc->a_f_write_child) {
			tc->crc_child = ~1;
			datagen2(addr + i * PAGE_SIZE, PAGE_SIZE, &tc->crc_child);
		}
		if (tc->a_f_read_child) {
			uint32_t crc = ~1;

			datasum(addr + i * PAGE_SIZE, PAGE_SIZE, &crc);
		}
	}

	return 0;
}

static int child_check(struct test_cases *test_cases)
{
	int i, ret = 0;
	uint8_t *addr = test_cases->addr;

	for (i = 0; i < TEST_CASES; i++) {
		uint32_t crc = ~1;
		struct test_case *tc = test_cases->tc + i;

		datasum(addr + i * PAGE_SIZE, PAGE_SIZE, &crc);
		if (crc != tc->crc_child) {
			fail("%d: %p data mismatch\n", i, addr + i * PAGE_SIZE);
			ret++;
		}
	}

	return ret;
}

static int parent_before_fork(struct test_cases *test_cases)
{
	uint8_t *addr;
	int i;

	if (test_cases->init(test_cases))
		return -1;

	addr = test_cases->addr;

	for (i = 0; i < TEST_CASES; i++) {
		struct test_case *tc = test_cases->tc + i;
		tc->num = i;

		if (tc->b_f_write) {
			tc->crc_parent = ~1;
			datagen2(addr + i * PAGE_SIZE, PAGE_SIZE, &tc->crc_parent);
			if (test_cases != &sep_tcs)
				tc->crc_child = tc->crc_parent;
		}
		if (tc->b_f_read) {
			uint32_t crc = ~1;

			datasum(addr + i * PAGE_SIZE, PAGE_SIZE, &crc);
		}
	}

	return 0;
}

static int parent_post_fork(struct test_cases *test_cases)
{
	uint8_t *addr = test_cases->addr;
	int i;

	for (i = 0; i < TEST_CASES; i++) {
		struct test_case *tc = test_cases->tc + i;

		if (tc->a_f_write_parent) {
			tc->crc_parent = ~1;
			datagen2(addr + i * PAGE_SIZE, PAGE_SIZE, &tc->crc_parent);
		}

		if (tc->a_f_read_parent) {
			uint32_t crc = ~1;

			datasum(addr + i * PAGE_SIZE, PAGE_SIZE, &crc);
		}
	}

	return 0;
}

static int parent_check(struct test_cases *test_cases)
{
	uint8_t *addr = test_cases->addr;
	int i, ret = 0;

	for (i = 0; i < TEST_CASES; i++) {
		struct test_case *tc = test_cases->tc + i;
		uint32_t crc = ~1;

		datasum(addr + i * PAGE_SIZE, PAGE_SIZE, &crc);
		if (crc != tc->crc_parent) {
			fail("%x: %p data mismatch\n", i, addr + i * PAGE_SIZE);
			ret++;
		}

		if (test_cases == &sep_tcs)
			continue;

		if (!tc->a_f_write_child &&
		    !tc->a_f_write_parent &&
		     tc->b_f_write)
			if (!is_cow(addr + i * PAGE_SIZE, child_pid, getpid())) {
				fail("%x: %p is not COW-ed\n", i, addr + i * PAGE_SIZE);
				ret++;
			}
	}

	return ret;
}

static int __init_cow(struct test_cases *tcs, int flags)
{
	int i;
	void *addr;

	addr = mmap(NULL, PAGE_SIZE * (TEST_CASES + 2),
				PROT_READ | PROT_WRITE,
				MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (addr == MAP_FAILED) {
		err("Can't allocate memory\n");
		return -1;
	}

	/*
	 * Guard pages are used for preventing merging with other vma-s.
	 * In parent cow-ed and coinciding regions can be merged, but
	 * in child they cannot be, so COW will not be restored. FIXME
	 */
	mmap(addr, PAGE_SIZE, PROT_NONE,
			MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
	addr += PAGE_SIZE;
	tcs->addr = addr;
	mmap(addr + PAGE_SIZE * TEST_CASES, PAGE_SIZE, PROT_NONE,
			MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED | flags, -1, 0);

	test_msg("cow_addr=%p\n", addr);
	for (i = 0; i < TEST_CASES; i++) {
		struct test_case *tc = tcs->tc + i;
		tc->crc_parent = zero_crc;
		tc->crc_child = zero_crc;
	}

	return 0;
}

static int init_cow(struct test_cases *tcs)
{
	return __init_cow(tcs, 0);
}

static int init_cow_gd(struct test_cases *tcs)
{
	return __init_cow(tcs, MAP_GROWSDOWN);
}

static int init_sep(struct test_cases *tcs)
{
	int i;

	tcs->addr = mmap(NULL, PAGE_SIZE * TEST_CASES,
				PROT_READ | PROT_WRITE,
				MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (tcs->addr == MAP_FAILED) {
		err("Can't allocate memory\n");
		return 1;
	}

	test_msg("sep_addr=%p\n", tcs->addr);
	for (i = 0; i < TEST_CASES; i++) {
		struct test_case *tc = tcs->tc + i;
		tc->crc_parent = zero_crc;
		tc->crc_child = zero_crc;
	}

	return 0;
}

static int init_file(struct test_cases *tcs)
{
	int i, ret, fd;
	uint8_t buf[PAGE_SIZE];
	uint32_t crc;

	fd = open(filename, O_TRUNC | O_CREAT | O_RDWR, 0600);
	if (fd < 0) {
		err("Unable to create a test file");
		return -1;
	}

	for (i = 0; i < TEST_CASES; i++) {
		struct test_case *tc = tcs->tc + i;
		crc = ~1;
		datagen2(buf, sizeof(buf), &crc);
		ret = write(fd, buf, sizeof(buf));
		if (ret != sizeof(buf)) {
			err("Unable to write data in a test file");
			return -1;
		}

		tc->crc_parent = crc;
		tc->crc_child = crc;
	}

	tcs->addr = mmap(NULL, PAGE_SIZE * TEST_CASES,
				PROT_READ | PROT_WRITE,
				MAP_PRIVATE | MAP_FILE, fd, 0);
	if (tcs->addr == MAP_FAILED) {
		err("Can't allocate memory\n");
		return 1;
	}

	test_msg("file_addr=%p\n", tcs->addr);
	close(fd);

	return 0;
}

static int child(task_waiter_t *child_waiter)
{
	int ret = 0;

	sep_tcs.addr = mmap(sep_tcs.addr, PAGE_SIZE * TEST_CASES,
				PROT_READ | PROT_WRITE,
				MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
	if (sep_tcs.addr == MAP_FAILED) {
		err("Can't allocate memory\n");
		return 1;
	}

	EXECUTE_ACTION(child_prep);

	task_waiter_complete_current(child_waiter);

	test_waitsig();

	ret = EXECUTE_ACTION(child_check);

	return ret ? -1: 0;
}

int main(int argc, char ** argv)
{
	uint8_t zero_page[PAGE_SIZE];
	int status, err = 0;
	task_waiter_t child_waiter;

	task_waiter_init(&child_waiter);

	memset(zero_page, 0, sizeof(zero_page));

	datasum(zero_page, sizeof(zero_page), &zero_crc);

	test_init(argc, argv);

	if (EXECUTE_ACTION(parent_before_fork))
		return 1;

	child_pid = test_fork();
	if (child_pid < 0)
		return -1;

	if (child_pid == 0)
		return child(&child_waiter);

	task_waiter_wait4(&child_waiter, child_pid);

	EXECUTE_ACTION(parent_post_fork);

	test_daemon();

	test_waitsig();

	err = EXECUTE_ACTION(parent_check);

	kill(child_pid, SIGTERM);
	wait(&status);

	unlink(filename);

	if (status)
		return 1;

	if (err == 0)
		pass();

	return 0;
}
