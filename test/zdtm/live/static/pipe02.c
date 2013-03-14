#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <linux/limits.h>

#include "zdtmtst.h"

const char *test_doc	= "Create two unshared descriptor for the one end of a pipe";
const char *test_author	= "Andrey Vagin <avagin@parallels.com>";

int main(int argc, char ** argv)
{
	int p[2], fd;
	int ret;
	char path[PATH_MAX];
	int flags;

	test_init(argc, argv);

	ret = pipe(p);
	if (ret)
		return 1;

	snprintf(path, sizeof(path), "/proc/self/fd/%d", p[0]);

	fd = open(path, O_RDONLY);
	if (fd == -1) {
		err("open");
		return 1;
	};

	if (fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK) == -1) {
		err("fcntl");
		return 1;
	}

	test_daemon();

	test_waitsig();

	flags = fcntl(fd, F_GETFL, 0);
	if ((flags & O_NONBLOCK) == 0) {
		fail("O_NONBLOCK are not restored for %d", fd);
		return 1;
	}

	flags = fcntl(p[0], F_GETFL, 0);
	if ((flags & O_NONBLOCK) != 0) {
		fail("Unexpected O_NONBLOCK on %d", p[0]);
		return 1;
	}

	pass();

	return 0;
}
