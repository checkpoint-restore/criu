#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "zdtmtst.h"

const char *test_doc	= "Check that we can migrate with a named pipe "
			"open";
const char *test_author	= "Roman Kagan <rkagan@parallels.com>";

char *filename;
TEST_OPTION(filename, string, "file name", 1);

#define BUF_SIZE (16 * 4096) /* A fifo buffer has 16 slots by default */

int main(int argc, char **argv)
{
	int fd;
	struct stat st;
	mode_t mode = S_IFIFO | 0700;
	uint8_t buf[BUF_SIZE];
	uint32_t crc;

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

	crc = ~0;
	datagen(buf, BUF_SIZE, &crc);
	if (write_data(fd, buf, BUF_SIZE)) {
		pr_perror("write() failed");
		return 1;
	}

	test_daemon();
	test_waitsig();

	if (read_data(fd, buf, BUF_SIZE)) {
		pr_perror("read() failed");
		return 1;
	}

	crc = ~0;
	if (datachk(buf, BUF_SIZE, &crc)) {
		fail("data corrupted\n");
		return 1;
	}

	if (close(fd) < 0) {
		fail("can't close %s: %m", filename);
		return 1;
	}

	if (stat(filename, &st) < 0) {
		fail("can't stat %s: %m", filename);
		return 1;
	}

	if (st.st_mode != mode) {
		fail("%s is no longer the fifo we had", filename);
		return 1;
	}

	if (unlink(filename) < 0) {
		fail("can't unlink %s: %m", filename);
		return 1;
	}

	pass();
	return 0;
}
