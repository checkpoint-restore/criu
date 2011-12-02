#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "zdtmtst.h"

const char *test_doc	= "Check that we can migrate with a named pipe "
			"open in a directory which has been mounted over by "
			"another filesystem";
const char *test_author	= "Roman Kagan <rkagan@parallels.com>";

char *dirname;
TEST_OPTION(dirname, string, "directory name", 1);

int main(int argc, char **argv)
{
	int fd;
	char path[256];
	struct stat st;
	mode_t mode = S_IFIFO | 0700;

	test_init(argc, argv);

	if (snprintf(path, sizeof(path), "%s/foo", dirname) >= sizeof(path)) {
		err("directory name \"%s\"is too long", dirname);
		exit(1);
	}

	if (mkdir(dirname, 0700)) {
		err("can't make directory %s: %m\n", dirname);
		exit(1);
	}

	if (mknod(path, mode, 0)) {
		err("can't make fifo \"%s\": %m\n", path);
		exit(1);
	}

	fd = open(path, O_RDWR);
	if (fd < 0) {
		err("can't open %s: %m\n", path);
		goto rmdir;
	}

	if (mount("rien", dirname, "tmpfs", 0, 0) < 0) {
		err("can't mount tmpfs over %s: %m", dirname);
		goto cleanup;
	}

	test_daemon();
	test_waitsig();

	if (umount(dirname) < 0) {
		fail("can't umount %s: %m", dirname);
		goto cleanup;
	}

	if (close(fd) < 0) {
		fail("can't close %s: %m", path);
		goto unlink;
	}

	if (stat(path, &st) < 0) {
		fail("can't stat %s: %m", path);
		goto unlink;
	}

	if (st.st_mode != mode) {
		fail("%s is no longer the fifo we had");
		goto unlink;
	}

	if (unlink(path) < 0) {
		fail("can't unlink %s: %m", path);
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
