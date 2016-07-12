#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>

#include "zdtmtst.h"

const char *test_doc	= "Open, unlink, change size, migrate, check size";

char *filename;
TEST_OPTION(filename, string, "file name", 1);

int main(int argc, char ** argv)
{
	int fd;
	size_t fsize=1000;
	uint8_t buf[fsize];
	struct stat fst;

	test_init(argc, argv);

	fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) {
		pr_perror("can't open %s", filename);
		exit(1);
	}

	if (fstat(fd, &fst) < 0) {
		pr_perror("can't get file info %s before", filename);
		goto failed;
	}

	if (fst.st_size != 0) {
		pr_perror("%s file size eq %ld", filename, (long)fst.st_size);
		goto failed;
	}

	if (unlink(filename) < 0) {
		pr_perror("can't unlink %s", filename);
		goto failed;
	}

#ifdef UNLINK_OVER
{
	int fdo;

	fdo = open(filename, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fdo < 0) {
		pr_perror("can't open %s", filename);
		exit(1);
	}
}
#endif

	memset(buf, '0', sizeof(buf));
	if (write(fd, buf, sizeof(buf)) != sizeof(buf)) {
		pr_perror("can't write %s", filename);
		goto failed;
	}

	test_daemon();
	test_waitsig();

	if (fstat(fd, &fst) < 0) {
		pr_perror("can't get %s file info after", filename);
		goto failed;
	}

	if (fst.st_size != fsize) {
		fail("(via fstat): file size changed to %ld", fst.st_size);
		goto failed;
	}

	fst.st_size = lseek(fd, 0, SEEK_END);
	if (fst.st_size != fsize) {
		fail("(via lseek): file size changed to %ld", fst.st_size);
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
