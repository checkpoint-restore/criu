#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "zdtmtst.h"

const char *test_doc	= "Check that a ghost fifo with data restored";
const char *test_author	= "Cyrill Gorcunov <gorcunov@openvz.org>";

char *filename;
TEST_OPTION(filename, string, "file name", 1);

int main(int argc, char **argv)
{
	int fd;
	int fd_ro;
	mode_t mode = S_IFIFO | 0700;
	uint8_t buf[256];
	uint32_t crc;
	int ret;

	test_init(argc, argv);

	if (mknod(filename, mode, 0)) {
		pr_perror("can't make fifo \"%s\"", filename);
		exit(1);
	}

	fd = open(filename, O_RDWR);
	if (fd < 0) {
		pr_perror("can't open %s", filename);
		return 1;
	}

	fd_ro = open(filename, O_RDONLY);
	if (fd_ro < 0) {
		pr_perror("can't open %s", filename);
		return 1;
	}

	crc = ~0;
	datagen(buf, sizeof(buf), &crc);
	ret = write(fd, buf, sizeof(buf));
	if (ret != sizeof(buf)) {
		pr_perror("write() failed");
		return 1;
	}

	if (unlink(filename) < 0) {
		fail("can't unlink %s", filename);
		return 1;
	}

	close(fd);

	test_daemon();
	test_waitsig();

	ret = read(fd_ro, buf, sizeof(buf));
	if (ret != sizeof(buf)) {
		pr_perror("read() failed");
		return 1;
	}

	crc = ~0;
	if (datachk(buf, sizeof(buf), &crc)) {
		fail("data corrupted");
		return 1;
	}

	if (close(fd_ro) < 0) {
		fail("can't close %s", filename);
		return 1;
	}

	pass();
	return 0;
}
