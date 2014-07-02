#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "zdtmtst.h"

const char *test_doc	= "Check that we can migrate with a device special file "
			  "open and unlinked before migration";
const char *test_author	= "Roman Kagan <rkagan@parallels.com>";

char *filename;
TEST_OPTION(filename, string, "file name", 1);

int main(int argc, char **argv)
{
	int fd;
	struct stat st;
	/* /dev/null params - sure to exist in a VPS */
	mode_t mode = S_IFCHR | 0700;
	dev_t dev = makedev(1, 3);

	test_init(argc, argv);

	if (mknod(filename, mode, dev)) {
		err("can't make device file \"%s\": %m\n", filename);
		exit(1);
	}

	fd = open(filename, O_RDWR);
	if (fd < 0) {
		err("can't open %s: %m\n", filename);
		goto out;
	}

	if (unlink(filename) < 0) {
		err("can't unlink %s: %m", filename);
		goto out;
	}

	test_daemon();
	test_waitsig();

	if (fstat(fd, &st) < 0) {
		fail("can't stat %s: %m", filename);
		goto out;
	}

	if (st.st_mode != mode || st.st_rdev != dev) {
		fail("%s is no longer the device file we had", filename);
		test_msg("mode %x want %x, dev %x want %x\n",
				st.st_mode, mode, st.st_rdev, dev);
		goto out;
	}

	if (close(fd) < 0) {
		fail("can't close %s: %m", filename);
		goto out;
	}

	if (unlink(filename) != -1 || errno != ENOENT) {
		fail("file %s should have been deleted before migration: unlink: %m\n");
		goto out;
	}

	pass();
out:
	close(fd);
	unlink(filename);
	return 0;
}
