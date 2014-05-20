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
	char *tname;
};

static int init_cow(struct test_cases *);
static int init_cow_gd(struct test_cases *tcs);
static int init_sep(struct test_cases *);
static int init_file(struct test_cases *);

static pid_t child_pid;

/*
 * A return code of -1 means an error running the test (e.g. error opening a
 * file, etc.).  A return code of 1 means failure, it means criu was not able
 * to checkpoint and/or restore the process properly.
 */
#define EXECUTE_ACTION(func) ({		\
	int __ret = 0;			\
	__ret |= func(&sep_tcs);	\
	__ret |= func(&cow_tcs);	\
	__ret |= func(&cow_gd_tcs);	\
	__ret |= func(&file_tcs);	\
	__ret;				\
})

struct test_cases cow_tcs = {.init = init_cow, .tname = "cow_tcs"},
		  sep_tcs = {.init = init_sep, .tname = "sep_tcs"},
		  file_tcs = {.init = init_file, .tname = "file_tcs"},
		  cow_gd_tcs = {.init = init_cow_gd, .tname = "cow_gd_tcs"};

uint32_t zero_crc = ~1;

static int is_cow(void *addr, pid_t pid_child, pid_t pid_parent,
		  uint64_t *map_child_ret, uint64_t *map_parent_ret)
{
	char buf[PATH_MAX];
	unsigned long pfn = (unsigned long) addr / PAGE_SIZE;
	uint64_t map_child, map_parent;
	int fd_child, fd_parent, ret, i;
	off_t lseek_ret;

	snprintf(buf, sizeof(buf), "/proc/%d/pagemap", pid_child);
	fd_child = open(buf, O_RDONLY);
	if (fd_child < 0) {
		err("Unable to open child pagemap file %s", buf);
		return -1;
	}

	snprintf(buf, sizeof(buf), "/proc/%d/pagemap", pid_parent);
	fd_parent = open(buf, O_RDONLY);
	if (fd_parent < 0) {
		err("Unable to open parent pagemap file %s", buf);
		return -1;
	}

	/*
	 * A page can be swapped or unswapped,
	 * so we should do several iterations.
	 */
	for (i = 0; i < 10; i++) {
		lseek_ret = lseek(fd_child, pfn * sizeof(map_child), SEEK_SET);
		if (lseek_ret == (off_t) -1) {
			err("Unable to seek child pagemap to virtual addr %#08lx",
			    pfn * PAGE_SIZE);
			return -1;
		}

		lseek_ret = lseek(fd_parent, pfn * sizeof(map_parent), SEEK_SET);
		if (lseek_ret == (off_t) -1) {
			err("Unable to seek parent pagemap to virtual addr %#08lx",
			    pfn * PAGE_SIZE);
			return -1;
		}

		ret = read(fd_child, &map_child, sizeof(map_child));
		if (ret != sizeof(map_child)) {
			err("Unable to read child pagemap at virtual addr %#08lx",
			    pfn * PAGE_SIZE);
			return -1;
		}

		ret = read(fd_parent, &map_parent, sizeof(map_parent));
		if (ret != sizeof(map_parent)) {
			err("Unable to read parent pagemap at virtual addr %#08lx",
			    pfn * PAGE_SIZE);
			return -1;
		}

		if (map_child == map_parent)
			break;
	}

	close(fd_child);
	close(fd_parent);

	if (map_child_ret)
		*map_child_ret = map_child;
	if (map_parent_ret)
		*map_parent_ret = map_parent;

	// Return 0 for success, 1 if the pages differ.
	return map_child != map_parent;
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
			errno = 0;
			fail("%s[%#x]: %p child data mismatch (expected [%04x] got [%04x])",
			     test_cases->tname, i, addr + i * PAGE_SIZE, tc->crc_child, crc);
			ret |= 1;
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
			errno = 0;
			fail("%s[%#x]: %p parent data mismatch (expected [%04x] got [%04x])",
			     test_cases->tname, i, addr + i * PAGE_SIZE, tc->crc_parent, crc);
			ret |= 1;
		}

		if (test_cases == &sep_tcs)
			continue;

		if (!tc->a_f_write_child &&
		    !tc->a_f_write_parent &&
		     tc->b_f_write) {
			uint64_t map_child, map_parent;
			int is_cow_ret;

			is_cow_ret = is_cow(addr + i * PAGE_SIZE, child_pid, getpid(),
					    &map_child, &map_parent);
			ret |= is_cow_ret;
			if (is_cow_ret == 1) {
				errno = 0;
				fail("%s[%#x]: %p is not COW-ed (pagemap of "
				     "child=[%#08lx], parent=[%#08lx])",
				     test_cases->tname, i, addr + i * PAGE_SIZE,
				     map_child, map_parent);
			}
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
		err("Can't allocate memory");
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

	test_msg("addr[%s]=%p\n", tcs->tname, tcs->addr);
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
		err("Can't allocate memory");
		return -1;
	}

	test_msg("addr[%s]=%p\n", tcs->tname, tcs->addr);
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
			err("Unable to write data in test file %s", filename);
			return -1;
		}

		tc->crc_parent = crc;
		tc->crc_child = crc;
	}

	tcs->addr = mmap(NULL, PAGE_SIZE * TEST_CASES,
				PROT_READ | PROT_WRITE,
				MAP_PRIVATE | MAP_FILE, fd, 0);
	if (tcs->addr == MAP_FAILED) {
		err("Can't allocate memory");
		return -1;
	}

	test_msg("addr[%s]=%p\n", tcs->tname, tcs->addr);
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
		err("Can't allocate memory");
		return -1;
	}

	EXECUTE_ACTION(child_prep);

	task_waiter_complete_current(child_waiter);

	test_waitsig();

	ret |= EXECUTE_ACTION(child_check);

	// Exit code of child process, so return 2 for a test error, 1 for a
	// test failure (child_check got mismatched checksums) and 0 for
	// success.
	return (ret < 0) ? 2 : (ret != 0);
}

int main(int argc, char ** argv)
{
	uint8_t zero_page[PAGE_SIZE];
	int status, ret = 0;
	task_waiter_t child_waiter;

	task_waiter_init(&child_waiter);

	memset(zero_page, 0, sizeof(zero_page));

	datasum(zero_page, sizeof(zero_page), &zero_crc);

	test_init(argc, argv);

	if (EXECUTE_ACTION(parent_before_fork))
		return 2;

	child_pid = test_fork();
	if (child_pid < 0) {
		err("Can't fork");
		return 2;
	}

	if (child_pid == 0)
		return child(&child_waiter);

	task_waiter_wait4(&child_waiter, child_pid);

	EXECUTE_ACTION(parent_post_fork);

	test_daemon();

	test_waitsig();

	ret |= EXECUTE_ACTION(parent_check);

	kill(child_pid, SIGTERM);
	wait(&status);

	unlink(filename);

	if (WIFEXITED(status) && WEXITSTATUS(status) != 2)
		ret |= WEXITSTATUS(status);
	else
		ret |= -1;

	if (ret == 0)
		pass();

	// Exit code, so return 2 for a test error, 1 for a test failure and 0
	// for success.
	return (ret < 0) ? 2 : (ret != 0);
}
