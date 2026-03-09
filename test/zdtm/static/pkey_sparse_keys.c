#include <errno.h>
#include <sys/mman.h>
#include <unistd.h>

#include "pkey-helpers.h"
#include "zdtmtst.h"

const char *test_doc = "Check sparse pkey allocation map restore with hole keys";
const char *test_author = "CRIU Team";

#if defined(__x86_64__)

int main(int argc, char **argv)
{
	int keys[5] = { -1, -1, -1, -1, -1 };
	int hole_keys[2];
	int pagesize;
	void *map = MAP_FAILED;
	int ret;
	int i;

	test_init(argc, argv);

	for (i = 0; i < 5; i++) {
		keys[i] = sys_pkey_alloc(0, 0);
		if (keys[i] >= 0)
			continue;

		if (errno == ENOSYS || errno == ENOSPC) {
			free_pkeys(keys, sizeof(keys) / sizeof(keys[0]));
			skip("not enough pkeys for sparse restore test");
			return 0;
		}

		pr_perror("pkey_alloc(%d) failed", i);
		free_pkeys(keys, sizeof(keys) / sizeof(keys[0]));
		return 1;
	}

	if (sys_pkey_free(keys[1]) || sys_pkey_free(keys[3])) {
		pr_perror("pkey_free(hole key) failed");
		free_pkeys(keys, sizeof(keys) / sizeof(keys[0]));
		return 1;
	}
	hole_keys[0] = keys[1];
	hole_keys[1] = keys[3];
	keys[1] = -1;
	keys[3] = -1;

	pagesize = getpagesize();
	map = mmap(NULL, pagesize, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (map == MAP_FAILED) {
		pr_perror("mmap failed");
		free_pkeys(keys, sizeof(keys) / sizeof(keys[0]));
		return 1;
	}

	if (sys_pkey_mprotect(map, pagesize, PROT_READ | PROT_WRITE, keys[4])) {
		pr_perror("pkey_mprotect(map, high_key) failed before C/R");
		munmap(map, pagesize);
		free_pkeys(keys, sizeof(keys) / sizeof(keys[0]));
		return 1;
	}

	test_daemon();
	test_waitsig();

	if (sys_pkey_mprotect(map, pagesize, PROT_READ | PROT_WRITE, keys[4])) {
		pr_perror("pkey_mprotect(map, high_key) failed after C/R");
		goto err;
	}

	/* key[2] was allocated before C/R but not bound to any VMA. */
	if (sys_pkey_mprotect(map, pagesize, PROT_READ | PROT_WRITE, keys[2])) {
		pr_perror("pkey_mprotect(map, allocated-unused key) failed after C/R");
		goto err;
	}

	errno = 0;
	ret = sys_pkey_mprotect(map, pagesize, PROT_READ | PROT_WRITE, hole_keys[0]);
	if (ret == 0 || errno != EINVAL) {
		fail("hole key[1]=%d unexpectedly usable after C/R, ret=%d errno=%d", hole_keys[0], ret, errno);
		goto err;
	}

	errno = 0;
	ret = sys_pkey_mprotect(map, pagesize, PROT_READ | PROT_WRITE, hole_keys[1]);
	if (ret == 0 || errno != EINVAL) {
		fail("hole key[3]=%d unexpectedly usable after C/R, ret=%d errno=%d", hole_keys[1], ret, errno);
		goto err;
	}

	munmap(map, pagesize);
	free_pkeys(keys, sizeof(keys) / sizeof(keys[0]));
	pass();
	return 0;

err:
	munmap(map, pagesize);
	free_pkeys(keys, sizeof(keys) / sizeof(keys[0]));
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
