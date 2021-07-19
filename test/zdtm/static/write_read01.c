#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>

#include "zdtmtst.h"

const char *test_doc = "Write and half way read file before migration, complete after";
const char *test_author = "Roman Kagan <rkagan@parallels.com>";

char *filename;
TEST_OPTION(filename, string, "file name", 1);

int main(int argc, char **argv)
{
	int fd;
	int len;
	uint32_t crc = ~0;
	uint8_t buf[1000000];

	test_init(argc, argv);

	fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) {
		pr_perror("can't open %s", filename);
		exit(1);
	}

	crc = ~0;
	datagen(buf, sizeof(buf), &crc);
	if (write(fd, buf, sizeof(buf)) != sizeof(buf)) {
		pr_perror("can't write %s", filename);
		exit(1);
	}

	close(fd);

	fd = open(filename, O_RDONLY);
	if (fd < 0) {
		pr_perror("can't open %s", filename);
		exit(1);
	}

	len = sizeof(buf) / 2;
	if (read(fd, buf, len) != len) {
		pr_perror("can't read %s", filename);
		exit(1);
	}

	test_daemon();
	test_waitsig();

	/* recover reading */
	if (read(fd, buf + len, sizeof(buf) - len) != (sizeof(buf) - len)) {
		fail("can't read %s", filename);
		goto out;
	}

	crc = ~0;
	if (datachk(buf, sizeof(buf), &crc)) {
		fail("CRC mismatch");
		goto out;
	}

	pass();
out:
	unlink(filename);
	return 0;
}
