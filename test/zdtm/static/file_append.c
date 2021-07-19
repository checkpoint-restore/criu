#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>

#include "zdtmtst.h"

const char *test_doc = "Check O_APPEND preserved";
const char *test_author = "Pavel Emelyanov <xemul@parallels.com>";

char *filename;
TEST_OPTION(filename, string, "file name", 1);

int main(int argc, char **argv)
{
	int fd, fd2, ret;
	char tmp[3];

	test_init(argc, argv);

	fd = open(filename, O_RDWR | O_CREAT | O_APPEND, 0644);
	if (fd == -1)
		return 1;

	fd2 = open(filename, O_RDWR, 0644);
	if (fd2 == -1)
		return 1;

	test_daemon();
	test_waitsig();

	if (write(fd2, "x", 1) != 1) {
		pr_perror("Can't write x");
		return 1;
	}

	if (write(fd, "y", 1) != 1) {
		pr_perror("Can't write y");
		return 1;
	}

	lseek(fd2, 0, SEEK_SET);
	ret = read(fd2, tmp, 3);
	if (ret != 2) {
		fail("Smth's wrong with file size");
		return 1;
	}
	tmp[2] = '\0';
	if (strcmp(tmp, "xy")) {
		fail("Smth's wron with file contents (%s)", tmp);
		return 1;
	}

	pass();

	return 0;
}
