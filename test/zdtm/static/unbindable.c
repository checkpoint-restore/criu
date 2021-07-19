#include <fcntl.h>
#include <unistd.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <linux/limits.h>

#include "zdtmtst.h"

const char *test_doc = "Check unbindable flag does not break mount restore";
const char *test_author = "Pavel Tikhomirov <ptikhomirov@virtuozzo.com>";

char *dirname;
TEST_OPTION(dirname, string, "directory name", 1);

int main(int argc, char **argv)
{
	char unbindable[PATH_MAX], bind_of_unbindable[PATH_MAX];
	char auxiliary[PATH_MAX];

	test_init(argc, argv);
	mkdir(dirname, 0700);

	snprintf(unbindable, sizeof(unbindable), "%s/unbindable", dirname);
	if (mkdir(unbindable, 0700)) {
		pr_perror("Unable to mkdir %s", unbindable);
		return 1;
	}
	if (mount("unbindable", unbindable, "tmpfs", 0, NULL)) {
		pr_perror("Unable to mount tmpfs to %s", unbindable);
		return 1;
	}

	snprintf(auxiliary, sizeof(auxiliary), "%s/unbindable/auxiliary", dirname);
	if (mkdir(auxiliary, 0700)) {
		pr_perror("Unable to mkdir %s", auxiliary);
		return 1;
	}

	snprintf(bind_of_unbindable, sizeof(bind_of_unbindable), "%s/bind_of_unbindable", dirname);
	if (mkdir(bind_of_unbindable, 0700)) {
		pr_perror("Unable to mkdir %s", bind_of_unbindable);
		return 1;
	}
	if (mount(auxiliary, bind_of_unbindable, NULL, MS_BIND, NULL)) {
		pr_perror("Unable to mount %s to %s", unbindable, bind_of_unbindable);
		return 1;
	}

	if (mount(NULL, unbindable, NULL, MS_UNBINDABLE, NULL)) {
		pr_perror("Unable to set %s unbindable", unbindable);
		return 1;
	}

	test_daemon();
	test_waitsig();

	if (umount(bind_of_unbindable)) {
		pr_perror("Unable to umount %s", bind_of_unbindable);
		return 1;
	}

	if (umount(unbindable)) {
		pr_perror("Unable to umount %s", unbindable);
		return 1;
	}

	pass();
	return 0;
}
