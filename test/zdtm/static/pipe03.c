#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "zdtmtst.h"

const char *test_doc	= "Check that pipes with a non-default size can be c/r-ed";
const char *test_author	= "Andrei Vagin <avagin@gmail.com>";

#define DATA_SIZE (1 << 20)
#define BUF_SIZE (4096)

int main(int argc, char **argv)
{
	int p[2], i;
	uint8_t buf[BUF_SIZE];
	uint32_t crc;

	test_init(argc, argv);

	if (pipe2(p, O_NONBLOCK)) {
		pr_perror("pipe");
		return 1;
	}

	if (fcntl(p[1], F_SETPIPE_SZ, DATA_SIZE) == -1) {
		pr_perror("Unable to change a pipe size");
		return 1;
	}

	crc = ~0;
	datagen(buf, BUF_SIZE, &crc);

	for (i = 0; i < DATA_SIZE / BUF_SIZE; i++) {
		if (write(p[1], buf, BUF_SIZE) != BUF_SIZE) {
			pr_perror("write");
			return 1;
		}
	}

	test_daemon();
	test_waitsig();

	for (i = 0; i < DATA_SIZE / BUF_SIZE; i++) {
		if (read(p[0], buf, BUF_SIZE) != BUF_SIZE) {
			pr_perror("read");
			return 1;
		}
	}

	pass();
	return 0;
}
