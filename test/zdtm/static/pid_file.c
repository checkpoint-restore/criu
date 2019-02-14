#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "zdtmtst.h"

const char *test_doc 	= "Check that environment didn't change";
const char *test_author	= "Andrei Vagin <avagin@gmail.com>";

int main(int argc, char **argv)
{
	int fd, fd2;
	struct stat st, st2;

	test_init(argc, argv);

	fd = open("/proc/1/status", O_RDONLY);
	if (fd < 0) {
		pr_perror("Unable to open /proc/1/status");
		return 1;
	}

	test_daemon();
	test_waitsig();

	fd2 = open("/proc/1/status", O_RDONLY);
	if (fd2 < 0) {
		pr_perror("Unable to open /proc/1/status");
		return 1;
	}
	if (fstat(fd, &st)) {
		pr_perror("fstat");
		return 1;
	}
	if (fstat(fd2, &st2)) {
		pr_perror("fstat");
		return 1;
	}
	close(fd);
	close(fd2);

	if (st.st_ino != st2.st_ino) {
		fail("inode numbers mismatch");
		return 1;
	}

	pass();
	return 0;
}
