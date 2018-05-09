#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <linux/limits.h>

#include "zdtmtst.h"

#ifndef __O_TMPFILE
#define __O_TMPFILE 020000000
#endif

#ifndef O_TMPFILE
#define O_TMPFILE (__O_TMPFILE | O_DIRECTORY)
#endif

const char *test_doc	= "Open, unlink, change size, seek, migrate, check size";

#ifdef UNLINK_FSTAT04
char *dirname;
TEST_OPTION(dirname, string, "directory name", 1);
#else
char *filename;
TEST_OPTION(filename, string, "file name", 1);
#endif

int main(int argc, char ** argv)
{
	int fd;
	size_t fsize=1000;
	mode_t mode;
	uid_t uid;
	gid_t gid;
	uint8_t buf[fsize];
	struct stat fst;
	uint32_t crc;
#ifdef UNLINK_FSTAT04
	char filename[PATH_MAX];
#endif

	test_init(argc, argv);

#ifdef UNLINK_FSTAT04
	snprintf(filename, sizeof(filename), "%s/test\\file'\n\"un%%linkfstat00", dirname);

	mkdir(dirname, 0700);
#endif
#ifndef UNLINK_FSTAT041
	fd = open(filename, O_RDWR | O_CREAT | O_TRUNC, 0644);
#else
	fd = open(dirname, O_RDWR | O_TMPFILE, 0644);
#endif
	if (fd < 0) {
		pr_perror("can't open %s", filename);
		exit(1);
	}

#ifdef UNLINK_FSTAT04
	if (chmod(dirname, 0500)) {
		pr_perror("chmod");
		exit(1);
	}
#endif

	if (fstat(fd, &fst) < 0) {
		pr_perror("can't get file info %s before", filename);
		goto failed;
	}

#ifndef UNLINK_FSTAT041
	if (unlink(filename) < 0) {
		pr_perror("can't unlink %s", filename);
		goto failed;
	}
#endif
	/* Change file size */
	if (fst.st_size != 0) {
		pr_perror("%s file size eq %ld", filename, (long)fst.st_size);
		goto failed;
	}

	crc = ~0;
	datagen(buf, sizeof(buf), &crc);
	if (write(fd, buf, sizeof(buf)) != sizeof(buf)) {
		pr_perror("can't write %s", filename);
		goto failed;
	}
	/* Change file mode */
	if ((fst.st_mode & S_IXOTH) == 0)
		mode = (fst.st_mode | S_IXOTH);
	else
		mode = (fst.st_mode ^ S_IXOTH);

	if (fchmod(fd, mode) < 0) {
		pr_perror("can't chmod %s", filename);
		goto failed;
	}

	if (getuid()) {
		uid = getuid();
		gid = getgid();
	} else {
		/* Change uid, gid */
		if (fchown(fd, (uid = fst.st_uid + 1), (gid = fst.st_gid + 1)) < 0) {
			pr_perror("can't chown %s", filename);
			goto failed;
		}
	}

	if (lseek(fd, 0, SEEK_SET) != 0) {
		pr_perror("can't reposition to 0");
		goto failed;
	}

	test_daemon();
	test_waitsig();

	if (fstat(fd, &fst) < 0) {
		pr_perror("can't get %s file info after", filename);
		goto failed;
	}

	/* Check file size */
	if (fst.st_size != fsize) {
		fail("(via fstat): file size changed to %ld",
				(long)fst.st_size);
		goto failed;
	}
	fst.st_size = lseek(fd, 0, SEEK_END);
	if (fst.st_size != fsize) {
		fail("(via lseek): file size changed to %ld",
				(long)fst.st_size);
		goto failed;
	}
	/* Check mode */
	if (fst.st_mode != mode) {
		fail("mode is changed to %o(%o)", fst.st_mode, mode);
		goto failed;
	}
	/* Check uid, gid */
	if (fst.st_uid != uid || fst.st_gid != gid) {
		fail("u(g)id changed: uid=%d(%d), gid=%d(%d)",
				fst.st_uid, uid, fst.st_gid, gid);
		goto failed;
	}

	if (lseek(fd, 0, SEEK_SET) != 0) {
		pr_perror("can't reposition to 0");
		goto failed;
	}
	if (read(fd, buf, sizeof(buf)) != sizeof(buf)) {
		fail("can't read %s: %m\n", filename);
		goto failed;
	}

	crc = ~0;
	if (datachk(buf, sizeof(buf), &crc)) {
		fail("CRC mismatch\n");
		goto failed;
	}

	close(fd);

	pass();
	return 0;
failed:
	unlink(filename);
	close(fd);
	return 1;
}
