#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "zdtmtst.h"

const char *test_doc = "Restore the executable without changing a guest O_PATH descriptor";
const char *test_author = "Simon Zhou <jp.zdm2008@gmail.com>";

int main(int argc, char **argv)
{
	char before[PATH_MAX], after[PATH_MAX], byte;
	struct stat original, restored;
	ssize_t length;
	int fd, flags;

	test_init(argc, argv);

	fd = open("/proc/self/exe", O_PATH | O_CLOEXEC);
	if (fd < 0) {
		pr_perror("Can't open executable with O_PATH");
		return 1;
	}

	length = readlink("/proc/self/exe", before, sizeof(before) - 1);
	if (length < 0 || fstat(fd, &original)) {
		pr_perror("Can't inspect original executable");
		return 1;
	}
	before[length] = '\0';

	test_daemon();
	test_waitsig();

	length = readlink("/proc/self/exe", after, sizeof(after) - 1);
	if (length < 0 || fstat(fd, &restored)) {
		pr_perror("Can't inspect restored executable");
		return 1;
	}
	after[length] = '\0';

	flags = fcntl(fd, F_GETFL);
	if (strcmp(before, after) || original.st_dev != restored.st_dev ||
	    original.st_ino != restored.st_ino || flags < 0 || !(flags & O_PATH)) {
		fail("Executable identity or guest O_PATH flags changed");
		return 1;
	}

	errno = 0;
	if (read(fd, &byte, 1) != -1 || errno != EBADF) {
		fail("Guest O_PATH descriptor became readable");
		return 1;
	}

	if (fcntl(fd, F_GETFD) != FD_CLOEXEC) {
		fail("Guest executable descriptor lost close-on-exec");
		return 1;
	}

	close(fd);
	pass();
	return 0;
}
