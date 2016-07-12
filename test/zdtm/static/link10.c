#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <signal.h>
#include <string.h>

#include "zdtmtst.h"

const char *test_doc	= "Migrate two hardlinked, open, and unlinked files";
const char *test_author	= "Roman Kagan <rkagan@parallels.com>";

char *filename;
TEST_OPTION(filename, string, "file name", 1);

int main(int argc, char ** argv)
{
	int fd, fd2 = 0;
	struct stat stat, stat2;
	char filename2[256];

	test_init(argc, argv);

	if (snprintf(filename2, sizeof(filename2), "%s.lnk", filename) >=
	    sizeof(filename2)) {
		pr_perror("filename %s is too long", filename);
		exit(1);
	}

	fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC | O_EXCL, 0644);
	if (fd < 0) {
		pr_perror("can't open %s", filename);
		exit(1);
	}

	if (link(filename, filename2) < 0) {
		pr_perror("can't link %s to %s", filename, filename2);
		goto unlink;
	}

	fd2 = open(filename2, O_RDONLY);
	if (fd < 0) {
		pr_perror("can't open %s", filename2);
		goto unlink;
	}

	unlink(filename2);
	unlink(filename);

	test_daemon();
	test_waitsig();

	if (fstat(fd, &stat) < 0 || fstat(fd2, &stat2) < 0) {
		fail("fstat failed: %m");
		goto out;
	}

	if (stat.st_ino != stat2.st_ino ||
	    stat.st_dev != stat2.st_dev) {
		fail("files are different: st_ino %lu != %lu or st_dev %lu != %lu",
		     (long unsigned)stat.st_ino, (long unsigned)stat2.st_ino,
		     (long unsigned)stat.st_dev, (long unsigned)stat2.st_dev);
	}

	pass();

out:
	close(fd);
	close(fd2);
	return 0;

unlink:
	close(fd);
	close(fd2);
	unlink(filename2);
	unlink(filename);
	return 1;
}
