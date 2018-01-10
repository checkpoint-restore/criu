#include <sys/types.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <sched.h>

#include "zdtmtst.h"
#include "lock.h"

const char *test_doc	= "Create file descriptors with different numbers. Check that they do not intersect with service fds";
const char *test_author	= "Kirill Tkhai <ktkhai@virtuozzo.com>";

int main(int argc, char **argv)
{
	unsigned int i, max_nr, flags;
	int fd, status, ret;
	struct rlimit rlim;
	char buf[16];
	pid_t pid;

	test_init(argc, argv);

	fd = open("/proc/sys/fs/nr_open", O_RDONLY);
	if (fd < 0) {
		fail("Can't open /proc/sys/fs/nr_open");
		exit(1);
	}

	ret = read(fd, buf, sizeof(buf));
	if (ret <= 0) {
		fail("Can't read");
		exit(1);
	}
	buf[ret] = '\0';

	max_nr = (unsigned int)atol(buf);
	if (max_nr == 0) {
		fail("max_nr");
		exit(1);
	}

	if (getrlimit(RLIMIT_NOFILE, &rlim)) {
		fail("getrlimit");
		exit(1);
	}

	rlim.rlim_cur = rlim.rlim_max;
	if (max_nr < rlim.rlim_cur)
		rlim.rlim_cur = max_nr;

	if (prlimit(getpid(), RLIMIT_NOFILE, &rlim, NULL)) {
		fail("rlimir: Can't setup RLIMIT_NOFILE for self");
		exit(1);
	}


	for (i = 1; (fd = (1 << i)) < (rlim.rlim_cur >> 1); i++) {
		FILE *fp = tmpfile();
		if (!fp) {
			fail("tmpfile");
			exit(1);
		}

		/* This fd really exists, skip it */
		if (fcntl(fd, F_GETFL) >= 0)
			continue;

		if (dup2(fileno(fp), fd) < 0) {
			fail("dup2");
			exit(1);
		}

		flags = SIGCHLD;
		if (i % 2 == 0)
			flags |= CLONE_FILES;

		pid = sys_clone_unified(flags, NULL, NULL, NULL, 0);
		if (pid < 0) {
			fail("fork");
			exit(1);
		} else if (!pid) {
			pause();
			exit(0);
		}
	}

	test_daemon();
	test_waitsig();

	/* Cleanup */
	while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
		if (kill(pid, SIGTERM) == 0)
			waitpid(-1, &status, 0); /* Ignore errors */
	}

	pass();

	return 0;
}
