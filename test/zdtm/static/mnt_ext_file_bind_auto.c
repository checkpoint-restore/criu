#include <sys/mount.h>
#include <linux/limits.h>
#include <sys/stat.h>
#include <sched.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>

#include "zdtmtst.h"

const char *test_doc = "Check if external file mount works";
const char *test_author = "Pavel Tikhomirov <ptikhomirov@virtuozzo.com>";

char *filename = "mnt_ext_file_bind_auto_bind_auto.file";
TEST_OPTION(filename, string, "file name", 1);

char *source = "mnt_ext_file_bind_auto_bind_auto.source";

int create_file(const char *path)
{
	int fd;

	fd = open(path, O_CREAT | O_RDWR, 0644);
	if (fd < 0) {
		pr_perror("open");
		return -1;
	}

	close(fd);
	return 0;
}

int main(int argc, char **argv)
{
	char *zdtm_newns = getenv("ZDTM_NEWNS");
	char *tmp = "/tmp/zdtm_ext_file_bind_auto.tmp";
	char *sourcefile = "/tmp/zdtm_ext_file_bind_auto.file";
	char *root, tmpfile[PATH_MAX], testfile[PATH_MAX];

	root = getenv("ZDTM_ROOT");
	if (root == NULL) {
		pr_perror("root");
		return 1;
	}

	if (!zdtm_newns) {
		pr_perror("ZDTM_NEWNS is not set");
		return 1;
	} else if (strcmp(zdtm_newns, "1")) {
		goto test;
	}

	/* Prepare file bindmount in criu root (source for external file bindmount) */
        mkdir(tmp, 0755);
        if (mount(source, tmp, "tmpfs", 0, NULL)) {
                pr_perror("mount tmpfs");
                return 1;
        }
        if (mount(NULL, tmp, NULL, MS_PRIVATE, NULL)) {
                pr_perror("make private");
                return 1;
        }

	sprintf(tmpfile, "%s/%s", tmp, filename);
	if (create_file(tmpfile))
		return 1;

	if (create_file(sourcefile))
		return 1;

	if (mount(tmpfile, sourcefile, NULL, MS_BIND, NULL)) {
		pr_perror("bind");
		return 1;
	}

	umount2(tmp, MNT_DETACH);

	/* Prepare file in test root (mount point for external file bindmount) */
	sprintf(testfile, "%s/%s", root, filename);
	if (create_file(testfile))
		return 1;

	/*
	 * Create temporary mntns, next mounts will not show up in criu mntns
	 * and will be inherited into test mntns
	 */
	if (unshare(CLONE_NEWNS)) {
		pr_perror("unshare");
		return 1;
	}

	if (mount(sourcefile, testfile, NULL, MS_BIND, NULL)) {
                pr_perror("bind");
                return 1;
        }
test:
	test_init(argc, argv);

	test_daemon();
	test_waitsig();

	pass();
	return 0;
}
