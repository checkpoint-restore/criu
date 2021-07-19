#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/sysmacros.h>

#include "zdtmtst.h"

const char *test_doc = "Check that we can migrate with a device special file "
		       "open in a directory which has been mounted over by "
		       "another filesystem";
const char *test_author = "Roman Kagan <rkagan@parallels.com>";

char *dirname;
TEST_OPTION(dirname, string, "directory name", 1);

int main(int argc, char **argv)
{
	int fd;
	char path[256];
	struct stat st;
	/* /dev/null params - sure to exist in a VPS */
	mode_t mode = S_IFCHR | 0700;
	dev_t dev = makedev(1, 3);

	test_init(argc, argv);

	if (snprintf(path, sizeof(path), "%s/foo", dirname) >= sizeof(path)) {
		pr_perror("directory name \"%s\"is too long", dirname);
		exit(1);
	}

	if (mkdir(dirname, 0700)) {
		pr_perror("can't make directory %s", dirname);
		exit(1);
	}

	if (mknod(path, mode, dev)) {
		pr_perror("can't make device file \"%s\"", path);
		exit(1);
	}

	fd = open(path, O_RDWR);
	if (fd < 0) {
		pr_perror("can't open %s", path);
		goto rmdir;
	}

	if (mount("rien", dirname, "tmpfs", 0, 0) < 0) {
		pr_perror("can't mount tmpfs over %s", dirname);
		goto cleanup;
	}

	test_daemon();
	test_waitsig();

	if (umount(dirname) < 0) {
		fail("can't umount %s", dirname);
		goto cleanup;
	}

	if (close(fd) < 0) {
		fail("can't close %s", path);
		goto unlink;
	}

	if (stat(path, &st) < 0) {
		fail("can't stat %s", path);
		goto unlink;
	}

	if (st.st_mode != mode || st.st_rdev != dev) {
		fail("%s is no longer the device file we had", path);
		goto unlink;
	}

	if (unlink(path) < 0) {
		fail("can't unlink %s", path);
		goto rmdir;
	}

	pass();
	goto rmdir;
cleanup:
	close(fd);
unlink:
	unlink(path);
rmdir:
	rmdir(dirname);
	return 0;
}
