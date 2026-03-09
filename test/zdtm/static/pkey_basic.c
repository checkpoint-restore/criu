#include <errno.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "pkey-helpers.h"
#include "zdtmtst.h"

const char *test_doc = "Check pkey allocation map + VMA pkey restore coverage";
const char *test_author = "CRIU Team";

#if defined(__x86_64__)

static void cleanup_mapping(void *a, void *b, int pagesize)
{
	if (a && a != MAP_FAILED)
		munmap(a, pagesize);
	if (b && b != MAP_FAILED)
		munmap(b, pagesize);
}

int main(int argc, char **argv)
{
	int key_used = -1, key_unused = -1;
	int pagesize;
	void *map_used = MAP_FAILED;
	void *map_unused = MAP_FAILED;

	test_init(argc, argv);

	key_used = sys_pkey_alloc(0, 0);
	if (key_used < 0) {
		if (errno == ENOSPC || errno == ENOSYS) {
			skip("pkey is unavailable");
			return 0;
		}
		pr_perror("pkey_alloc(key_used) failed");
		return 1;
	}

	key_unused = sys_pkey_alloc(0, 0);
	if (key_unused < 0) {
		sys_pkey_free(key_used);
		if (errno == ENOSPC || errno == ENOSYS) {
			skip("not enough pkeys for coverage test");
			return 0;
		}
		pr_perror("pkey_alloc(key_unused) failed");
		return 1;
	}

	pagesize = getpagesize();
	map_used = mmap(NULL, pagesize, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	map_unused = mmap(NULL, pagesize, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (map_used == MAP_FAILED || map_unused == MAP_FAILED) {
		pr_perror("mmap failed");
		goto err;
	}

	/* Bind only key_used before C/R; key_unused stays allocated-but-unused. */
	if (sys_pkey_mprotect(map_used, pagesize, PROT_READ | PROT_WRITE, key_used)) {
		pr_perror("pkey_mprotect(map_used, key_used) failed before C/R");
		goto err;
	}

	memset(map_used, 0x11, pagesize);
	memset(map_unused, 0x22, pagesize);

	test_daemon();
	test_waitsig();

	/*
	 * 1) key_used should still be valid for explicit pkey_mprotect.
	 * 2) key_unused was never bound to any VMA before C/R; this checks that
	 *    mm-level pkey allocation map restore preserved allocated-but-unused key.
	 */
	if (sys_pkey_mprotect(map_used, pagesize, PROT_READ | PROT_WRITE, key_used)) {
		pr_perror("pkey_mprotect(map_used, key_used) failed after C/R");
		goto err;
	}

	if (sys_pkey_mprotect(map_unused, pagesize, PROT_READ | PROT_WRITE, key_unused)) {
		pr_perror("pkey_mprotect(map_unused, key_unused) failed after C/R");
		goto err;
	}

	sys_pkey_free(key_unused);
	sys_pkey_free(key_used);
	cleanup_mapping(map_used, map_unused, pagesize);
	pass();
	return 0;

err:
	if (key_unused >= 0)
		sys_pkey_free(key_unused);
	if (key_used >= 0)
		sys_pkey_free(key_used);
	cleanup_mapping(map_used, map_unused, pagesize);
	return 1;
}

#else

int main(int argc, char **argv)
{
	test_init(argc, argv);
	skip("Unsupported arch");
	return 0;
}

#endif
