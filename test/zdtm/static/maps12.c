#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <setjmp.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <linux/limits.h>
#include "zdtmtst.h"

const char *test_doc = "Test madvise(MADV_GUARD_INSTALL)";
const char *test_author = "Alexander Mikhalitsyn <aleksandr.mikhalitsyn@canonical.com>";
/* some parts of code were taken from Linux kernel's kselftest guard-pages.c
   written by Lorenzo Stoakes <lorenzo.stoakes@oracle.com> */

char *filename;
int fd;
TEST_OPTION(filename, string, "file name", 1);

#ifndef MADV_GUARD_INSTALL
#define MADV_GUARD_INSTALL 102
#endif

uint8_t *map_base;

struct {
	unsigned int pages_num;
	bool filemap;
} vmas[] = {
	{ 2, false },
	{ 2, false },
	{ 2, false },
	{ 2, true },
	{ 2, true },
	{ 2, true },
};

struct {
	bool guarded;
	bool wipeonfork;
} pages[] = {
	{ false, false }, /* vmas[0] */
	{ true, false },
	{ true, false }, /* vmas[1] */
	{ false, false },
	{ false, false }, /* vmas[2] */
	{ true, true },
	{ true, false }, /* vmas[3] */
	{ false, false },
	{ true, false }, /* vmas[4] */
	{ true, false },
	{ false, false }, /* vmas[5] */
	{ true, false },
};

static volatile sig_atomic_t signal_jump_set;
static sigjmp_buf signal_jmp_buf;

static void handle_sigsegv(int signo)
{
	if (!signal_jump_set)
		return;

	siglongjmp(signal_jmp_buf, 1);
}

static bool try_write_to_addr(uint8_t *ptr)
{
	bool failed;

	/* Tell signal handler to jump back here on fatal signal. */
	signal_jump_set = true;
	/* If a fatal signal arose, we will jump back here and failed is set. */
	failed = sigsetjmp(signal_jmp_buf, 1) != 0;

	if (!failed)
		*ptr = 'x';

	signal_jump_set = false;
	return !failed;
}

static int setup_sigsegv_handler(void)
{
	uint8_t write_me;

	if (signal(SIGSEGV, handle_sigsegv) == SIG_ERR) {
		pr_perror("setting SIGSEGV handler failed");
		return 1;
	}

	/* ensure that try_write_to_addr() works properly */
	if (!try_write_to_addr(&write_me)) {
		pr_err("Failed to write at valid addr. Buggy try_write_to_addr()?\n");
		return 1;
	}

	if (try_write_to_addr(NULL)) {
		pr_err("Failed to detect an invalid write. Buggy try_write_to_addr()?\n");
		return 1;
	}

	return 0;
}

static inline void *mmap_pages(void *addr_hint, unsigned int count, bool filemap)
{
	char *map;

	map = mmap(addr_hint, count * PAGE_SIZE, PROT_WRITE | PROT_READ,
		   MAP_PRIVATE | (filemap ? 0 : MAP_ANONYMOUS) | (addr_hint ? MAP_FIXED : 0),
		   filemap ? fd : -1,
		   filemap ? (off_t)((intptr_t)addr_hint - (intptr_t)map_base) : 0);
	if (map == MAP_FAILED || (addr_hint && (map != addr_hint)))
		return MAP_FAILED;

	return map;
}

static int __check_guards(const char *when, bool in_child)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(pages); i++) {
		/*
		 * Skip pages that were never guarded, and also those
		 * that were, but have MADV_WIPEONFORK which means that
		 * guards were removed on fork.
		 */
		if (!pages[i].guarded || (in_child && pages[i].wipeonfork))
			continue;

		if (try_write_to_addr(&map_base[i * PAGE_SIZE])) {
			pr_err("successful write to a guarded area %d %s C/R\n",
			       i, when);
			return 1;
		}
	}

	return 0;
}

static int check_guards(const char *when)
{
	int status;
	pid_t pid;

	/*
	 * First of all, check that guards are on their places
	 * in a main test process.
	 */
	if (__check_guards(when, false)) {
		return 1;
	}

	/*
	 * Now, check that guards are on their places
	 * after fork(). This allows to ensure that
	 * combo MADV_WIPEONFORK + MADV_GUARD_INSTALL
	 * is restored properly too.
	 */

	pid = test_fork();
	if (pid < 0) {
		pr_perror("check_guards: fork failed");
		return 1;
	}

	if (pid == 0) {
		if (__check_guards(when, true)) {
			pr_err("check_guards(\"%s\") failed in child\n", when);
			exit(1);
		}

		exit(0);
	}

	if (waitpid(pid, &status, 0) != pid) {
		pr_perror("check_guards: waitpid");
		return 1;
	}

	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
		pr_err("check_guards: process didn't exit cleanly: status=%d\n", status);
		return 1;
	}

	return 0;
}

static void gen_pages_data(void)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(pages); i++) {
		uint32_t crc;

		if (pages[i].guarded)
			continue;

		crc = ~0;
		datagen(&map_base[i * PAGE_SIZE], PAGE_SIZE, &crc);
	}
}

static int set_pages_madvs(void)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(pages); i++) {
		if (pages[i].guarded) {
			if (madvise(&map_base[i * PAGE_SIZE], PAGE_SIZE,
				    MADV_GUARD_INSTALL)) {
				pr_perror("MADV_GUARD_INSTALL failed on page %d", i);
				return 1;
			}
		}

		if (pages[i].wipeonfork) {
			if (madvise(&map_base[i * PAGE_SIZE], PAGE_SIZE,
				    MADV_WIPEONFORK)) {
				pr_perror("MADV_WIPEONFORK failed on page %d", i);
				return 1;
			}
		}
	}

	return 0;
}

static int check_pages_data(void)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(pages); i++) {
		uint32_t crc;

		if (pages[i].guarded)
			continue;

		crc = ~0;
		if (datachk(&map_base[i * PAGE_SIZE], PAGE_SIZE, &crc)) {
			pr_err("Page %d is corrupted\n", i);
			return 1;
		}
	}

	return 0;
}

static int prepare_vmas(void)
{
	char *map;
	int i, shift;

	shift = 0;
	for (i = 0; i < ARRAY_SIZE(vmas); i++) {
		map = mmap_pages(&map_base[shift * PAGE_SIZE],
				 vmas[i].pages_num, vmas[i].filemap);
		if (map == MAP_FAILED) {
			pr_err("mmap of [%d,%d] pages failed\n",
			       shift, shift + vmas[i].pages_num);
			return 1;
		}

		shift += vmas[i].pages_num;
	}

	if (shift != ARRAY_SIZE(pages)) {
		pr_err("Different number of pages in vmas and pages arrays.\n");
		return 1;
	}

	return 0;
}

int main(int argc, char **argv)
{
	unsigned int pages_num = ARRAY_SIZE(pages);

	test_init(argc, argv);

	fd = open(filename, O_TRUNC | O_CREAT | O_RDWR, 0600);
	if (fd < 0) {
		pr_perror("Unable to create a test file");
		return -1;
	}

	if (ftruncate(fd, pages_num * PAGE_SIZE)) {
		pr_perror("Unable to ftruncate a test file");
		return -1;
	}

	if (setup_sigsegv_handler()) {
		pr_err("setup_sigsegv_handler() failed\n");
		return 1;
	}

	/* let's find a large enough area in address space */
	map_base = mmap_pages(NULL, pages_num, false);
	if (map_base == MAP_FAILED) {
		pr_err("mmap of %d pages failed\n", pages_num);
		return 1;
	}

	/*
	 * Now we know that we have a free vm address space area
	 * [map_base, map_base + pages_num * PAGE_SIZE).
	 * We can use (map_base) as a hint for our further mmaps.
	 */
	if (prepare_vmas()) {
		pr_err("prepare_vmas() failed\n");
		return 1;
	}

	/* fill non-guarded pages with data and preserve checksums */
	gen_pages_data();

	if (set_pages_madvs()) {
		pr_err("set_pages_madvs() failed\n");
		return 1;
	}

	/* ensure that madvise(MADV_GUARD_INSTALL) works like expected */
	if (check_guards("before")) {
		pr_err("check_guards(\"before\") failed\n");
		return 1;
	}

	test_daemon();
	test_waitsig();

	/* ensure that guards are at their places */
	if (check_guards("after")) {
		fail("check_guards(\"after\") failed");
		return 1;
	}

	/* check that non-guarded pages still contain original data */
	if (check_pages_data()) {
		fail("check_pages_data() failed");
		return 1;
	}

	pass();
	munmap(map_base, pages_num * PAGE_SIZE);
	close(fd);
	return 0;
}
