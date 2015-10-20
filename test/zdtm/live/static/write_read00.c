#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>

#include "zdtmtst.h"

const char *test_doc	= "Write file before migration, read after";
const char *test_author	= "Roman Kagan <rkagan@parallels.com>";

char *filename;
TEST_OPTION(filename, string, "file name", 1);

int main(int argc, char ** argv)
{
	int fd;
	uint32_t crc;
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

	test_daemon();
	test_waitsig();

	fd = open(filename, O_RDONLY);
	if (fd < 0) {
		fail("can't open %s: %m\n", filename);
		exit(1);
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

	pass();
out:
	unlink(filename);
	return 0;
}
