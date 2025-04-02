#include <sys/mount.h>

#include "zdtmtst.h"

const char *test_doc = "Check if root mount remains read-only after c/r";
const char *test_author = "Pavel Tikhomirov <ptikhomirov@virtuozzo.com>";

char *dirname;
TEST_OPTION(dirname, string, "directory name", 1);

int main(int argc, char **argv)
{
	test_init(argc, argv);

	if (mount(NULL, "/", NULL, MS_REMOUNT | MS_RDONLY | MS_BIND, NULL)) {
		pr_perror("mount");
		return 1;
	}

	test_daemon();
	test_waitsig();

	/*
	 * Note: In zdtm.py:check_visible_state() we already check for all
	 * tests, that all mounts in the test's mount namespace remain the
	 * same, by comparing mountinfo before and after c/r. So rw/ro mount
	 * option inconsistency will be detected there and we don't need to
	 * check it in the test itself.
	 */
	pass();
	return 0;
}
