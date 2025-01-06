#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>

#include "zdtmtst.h"

const char *test_doc = "Checkpointing/restore of big (2Gb) unlinked files";

char *filename;
TEST_OPTION(filename, string, "file name", 1);

int main(int argc, char **argv)
{
	int fd;
	char buf[1000000];
	off64_t offset = 0x80002000ULL;
	size_t count;

	test_init(argc, argv);

	fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC | O_LARGEFILE, 0644);
	if (fd < 0) {
		pr_perror("can't open %s", filename);
		exit(1);
	}

	if (lseek64(fd, offset, SEEK_SET) < 0) {
		pr_perror("can't lseek %s, offset= %llx", filename, (long long unsigned)offset);
		goto failed;
	}

	count = sizeof(buf);
	memset(buf, 0, count);
	if (write(fd, buf, count) != count) {
		pr_perror("can't write %s", filename);
		goto failed;
	}

	if (unlink(filename) < 0) {
		pr_perror("can't unlink %s", filename);
		goto failed;
	}

	test_daemon();
	test_waitsig();

	close(fd);

	pass();
	return 0;
failed:
	unlink(filename);
	close(fd);
	return 1;
}
