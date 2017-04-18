#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>

#include "zdtmtst.h"

const char *test_doc	= "Open, link, unlink x2, change size, migrate, check size";

char *filename;
TEST_OPTION(filename, string, "file name", 1);
static char link_name[1024];

int main(int argc, char ** argv)
{
	int fd[2];
	size_t fsize=1000;
	uint8_t buf[fsize];
	struct stat fst, fst2;

	test_init(argc, argv);

	fd[0] = open(filename, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fd[0] < 0) {
		pr_perror("can't open %s", filename);
		exit(1);
	}

	sprintf(link_name, "%s.link", filename);
	if (link(filename, link_name)) {
		pr_perror("can't link files");
		goto failed0;
	}

	fd[1] = open(link_name, O_RDONLY);
	if (fd[1] < 0) {
		pr_perror("can't open %s", link_name);
		goto failed0;
	}

	if (fstat(fd[0], &fst) < 0) {
		pr_perror("can't get file info %s before", filename);
		goto failed;
	}

	if (fst.st_size != 0) {
		pr_perror("%s file size eq %lld",
				filename, (long long)fst.st_size);
		goto failed;
	}

	if (unlink(filename) < 0) {
		pr_perror("can't unlink %s", filename);
		goto failed;
	}

	if (unlink(link_name) < 0) {
		pr_perror("can't unlink %s", link_name);
		goto failed;
	}

	memset(buf, '0', sizeof(buf));
	if (write(fd[0], buf, sizeof(buf)) != sizeof(buf)) {
		pr_perror("can't write %s", filename);
		goto failed;
	}

	test_daemon();
	test_waitsig();

	if (fstat(fd[0], &fst) < 0) {
		pr_perror("can't get %s file info after", filename);
		goto failed;
	}

	if (fstat(fd[1], &fst2) < 0) {
		pr_perror("can't get %s file2 info after", link_name);
		goto failed;
	}

	if ((fst.st_dev != fst2.st_dev) || (fst.st_ino != fst2.st_ino)) {
		fail("files differ after restore\n");
		goto failed;
	}

	if (fst.st_size != fsize) {
		fail("(via fstat): file size changed to %lld",
				(long long)fst.st_size);
		goto failed;
	}

	fst.st_size = lseek(fd[0], 0, SEEK_END);
	if (fst.st_size != fsize) {
		fail("(via lseek): file size changed to %lld",
				(long long)fst.st_size);
		goto failed;
	}

	close(fd[0]);
	close(fd[1]);

	pass();
	return 0;

failed:
	unlink(link_name);
	close(fd[1]);
failed0:
	unlink(filename);
	close(fd[0]);
	return 1;
}
