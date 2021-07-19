#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>

#include "zdtmtst.h"

const char *test_doc = "Write file half way before migration, complete and read after";
const char *test_author = "Roman Kagan <rkagan@parallels.com>";

char *filename;
TEST_OPTION(filename, string, "file name", 1);

int main(int argc, char **argv)
{
	int fd, fd1;
	int len, full_len;
	uint32_t crc;
	uint8_t buf[1000000];
	char str[32];

	test_init(argc, argv);

	fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) {
		pr_perror("can't open %s", filename);
		exit(1);
	}

	crc = ~0;
	datagen(buf, sizeof(buf), &crc);

	full_len = sizeof(buf);
	// create standard file
	sprintf(str, "standard_%s", filename);
	fd1 = open(str, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (write(fd1, buf, full_len) != full_len) {
		pr_perror("can't write %s", str);
		exit(1);
	}
	close(fd1);

	len = sizeof(buf) / 2;
	if (write(fd, buf, len) != len) {
		pr_perror("can't write %s", filename);
		exit(1);
	}

	test_daemon();
	test_waitsig();

	if (write(fd, buf + len, sizeof(buf) - len) != (sizeof(buf) - len)) {
		fail("can't write %s", filename);
		goto out;
	}

	close(fd);

	fd = open(filename, O_RDONLY);
	if (fd < 0) {
		fail("can't open %s", filename);
		return 1;
	}

	if (read(fd, buf, full_len) != full_len) {
		fail("can't read %s", filename);
		return 1;
	}

	crc = ~0;
	if (datachk(buf, full_len, &crc)) {
		fail("CRC mismatch");
		return 1;
	}

	pass();
out:
	unlink(filename);
	return 0;
}
