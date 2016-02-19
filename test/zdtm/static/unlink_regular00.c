#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <unistd.h>
#include <string.h>
#include <limits.h>

#include "zdtmtst.h"

const char *test_doc = "Checkpointing/restore of unlinked file inside unlinked directory";
const char *test_author	= "Kirill Tkhai <ktkhai@virtuozzo.com>";

char *dirname;
TEST_OPTION(dirname, string, "directory name", 1);

#define SUBDIR "subdir"
#define FNAME "testfile"
#define MSG "Hello!!!111"

int main(int argc, char ** argv)
{
	char subdir[PATH_MAX], fname[PATH_MAX], lname[PATH_MAX];
	char buf[sizeof(MSG) + 1];
	int fd, ret = -1;

	test_init(argc, argv);

	memset(buf, 0, sizeof(buf));

	if (mkdir(dirname, 0777)) {
		fail("can't create %s", dirname);
		exit(1);
	}

	if (mount("none", dirname, "tmpfs", 0, "") < 0) {
		fail("can't mount tmpfs to %s", dirname);
		goto rm_topdir;
	}

	sprintf(subdir, "%s/" SUBDIR, dirname);

	if (mkdir(subdir, 0777)) {
		fail("can't create %s", subdir);
		goto umount;
	}

	sprintf(fname, "%s/" SUBDIR "/" FNAME, dirname);
	sprintf(lname, "%s/" FNAME, dirname);

	fd = open(fname, O_RDWR | O_CREAT, 0644);
	if (fd < 0) {
		fail("can't open %s", fname);
		rmdir(subdir);
		goto umount;
	}

	if (link(fname, lname) < 0) {
		fail("can't link %s to %s", fname, lname);
		unlink(fname);
		rmdir(subdir);
		goto umount;
	}

	if (unlink(fname) || rmdir(subdir)) {
		fail("can't unlink %s or %s", fname, subdir);
		goto close_file;
	}

	if (write(fd, MSG, sizeof(MSG)) != sizeof(MSG)) {
		fail("can't write %s", fname);
		goto close_file;
	}

	test_daemon();
	test_waitsig();

	if (lseek(fd, 0, SEEK_SET) != 0) {
		fail("can't lseek %s", fname);
		goto close_file;
	}

	if (read(fd, buf, sizeof(MSG)) != sizeof(MSG)) {
		fail("can't read %s", fname);
		goto close_file;
	}

	if (strcmp(buf, MSG)) {
		fail("content differs: %s, %s, sizeof=%d", buf, MSG, sizeof(MSG));
		goto close_file;
	}

	ret = 0;
	pass();

close_file:
	close(fd);
	unlink(lname);
umount:
	if (umount(dirname) < 0)
		pr_err("Can't umount\n");
rm_topdir:
	if (rmdir(dirname) < 0)
		pr_err("Can't rmdir()\n");

	return ret;
}
