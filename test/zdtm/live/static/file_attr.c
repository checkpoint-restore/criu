#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <utime.h>
#include <sys/stat.h>

#include "zdtmtst.h"

const char *test_doc	= "Check that attributes and content of an open, "
			  "written to, and then unlinked file migrate "
			  "correctly";
const char *test_author	= "Roman Kagan <rkagan@parallels.com>";

char *filename;
TEST_OPTION(filename, string, "file name", 1);
#define DEF_PERMS 06604		/* -rwS--Sr--, really esoteric one */
unsigned int perms = DEF_PERMS;
TEST_OPTION(perms, uint, "permissions to set on file "
	    "(default " __stringify(DEF_PERMS) ")", 0);
#define DEF_MTIME 123456	/* another really esoteric one */
unsigned int mtime = DEF_MTIME;
TEST_OPTION(mtime, uint, "mtime to set on file "
	    "(default " __stringify(DEF_MTIME) ")", 0);


int main(int argc, char ** argv)
{
	int fd;
	struct utimbuf ut;
	uint32_t crc;
	struct stat st;
	uint8_t buf[1000000];

	test_init(argc, argv);

	fd = open(filename, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) {
		pr_perror("can't open %s", filename);
		exit(1);
	}

	crc = ~0;
	datagen(buf, sizeof(buf), &crc);
	if (write(fd, buf, sizeof(buf)) != sizeof(buf)) {
		pr_perror("can't write to %s", filename);
		exit(1);
	}

	ut = (struct utimbuf) {
		.actime = 0,
		.modtime = mtime,
	};
	if (utime(filename, &ut)) {
		pr_perror("can't set modtime %d on %s", mtime, filename);
		exit(1);
	}

	if (fchmod(fd, perms)) {
		pr_perror("can't set perms %o on %s", perms, filename);
		exit(1);
	}

	if (unlink(filename)) {
		pr_perror("can't unlink %s", filename);
		exit(1);
	}

	test_daemon();
	test_waitsig();

	if (lseek(fd, 0, SEEK_SET) < 0) {
		fail("lseeking to the beginning of file failed: %m\n");
		goto out;
	}

	if (read(fd, buf, sizeof(buf)) != sizeof(buf)) {
		fail("can't read %s: %m\n", filename);
		goto out;
	}

	crc = ~0;
	if (datachk(buf, sizeof(buf), &crc)) {
		fail("CRC mismatch\n");
		goto out;
	}

	if (fstat(fd, &st) < 0) {
		fail("can't fstat %s: %m", filename);
		goto out;
	}

	if ((st.st_mode & 07777) != perms) {
		fail("permissions have changed");
		goto out;
	}

	if (st.st_mtime != mtime) {
		fail("modification time has changed");
		goto out;
	}

	if (close(fd)) {
		fail("close failed: %m\n");
		goto out_noclose;
	}

	if (unlink(filename) != -1 || errno != ENOENT) {
		fail("file %s should have been deleted before migration: unlink: %m\n");
		goto out_noclose;
	}

	pass();

out:
	close(fd);
out_noclose:
	return 0;
}
