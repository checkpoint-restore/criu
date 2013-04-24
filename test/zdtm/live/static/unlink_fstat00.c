#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>

#include "zdtmtst.h"

const char *test_doc	= "Open, unlink, change size, seek, migrate, check size";

char *filename;
TEST_OPTION(filename, string, "file name", 1);

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

	test_init(argc, argv);

	fd = open(filename, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) {
		err("can't open %s: %m\n", filename);
		exit(1);
	}

	if (fstat(fd, &fst) < 0) {
		err("can't get file info %s before: %m\n", filename);
		goto failed;
	}

	if (unlink(filename) < 0) {
		err("can't unlink %s: %m\n", filename);
		goto failed;
	}
	/* Change file size */
	if (fst.st_size != 0) {
		err("%s file size eq %d\n", fst.st_size);
		goto failed;
	}

	crc = ~0;
	datagen(buf, sizeof(buf), &crc);
	if (write(fd, buf, sizeof(buf)) != sizeof(buf)) {
		err("can't write %s: %m\n", filename);
		goto failed;
	}
	/* Change file mode */
	if ((fst.st_mode & S_IXOTH) == 0)
		mode = (fst.st_mode | S_IXOTH);
	else
		mode = (fst.st_mode ^ S_IXOTH);

	if (fchmod(fd, mode) < 0) {
		err("can't chmod %s: %m\n", filename);
		goto failed;
	}

	if (getuid()) {
		uid = getuid();
		gid = getgid();
	} else {
		/* Change uid, gid */
		if (fchown(fd, (uid = fst.st_uid + 1), (gid = fst.st_gid + 1)) < 0) {
			err("can't chown %s: %m\n", filename);
			goto failed;
		}
	}

	if (lseek(fd, 0, SEEK_SET) != 0) {
		err("can't reposition to 0: %m");
		goto failed;
	}

	test_daemon();
	test_waitsig();

	if (fstat(fd, &fst) < 0) {
		err("can't get %s file info after: %m\n", filename);
		goto failed;
	}

	/* Check file size */
	if (fst.st_size != fsize) {
		fail("(via fstat): file size changed to %d", fst.st_size);
		goto failed;
	}
	fst.st_size = lseek(fd, 0, SEEK_END);
	if (fst.st_size != fsize) {
		fail("(via lseek): file size changed to %d", fst.st_size);
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
		err("can't reposition to 0: %m");
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
