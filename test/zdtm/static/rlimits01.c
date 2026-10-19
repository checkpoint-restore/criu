#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <unistd.h>

#include "zdtmtst.h"

const char *test_doc = "Check that a task sandboxed by RLIMIT_NOFILE and RLIMIT_FSIZE is dumped and survives";
const char *test_author = "Simon Zhou <jp.zdm2008@gmail.com>";

/*
 * dhcpcd's privilege-separated helpers lower RLIMIT_NOFILE to the number of
 * descriptors they hold, so the parasite cannot get one of its own, and
 * RLIMIT_FSIZE to nothing, so its first log write would kill them with
 * SIGXFSZ. The test keeps enough RLIMIT_FSIZE for its own output; CRIU's
 * log is far past that by the time the parasite writes to it.
 */
#define NOFILE 64
#define FSIZE  4096

static int fill_slots(void)
{
	int fd;

	do {
		fd = open("/dev/null", O_RDONLY);
		if (fd < 0) {
			pr_perror("Can't open /dev/null");
			return -1;
		}
	} while (fd < NOFILE - 1);

	if (fd != NOFILE - 1) {
		pr_err("Descriptor %d is above the limit %d\n", fd, NOFILE);
		return -1;
	}

	return 0;
}

static int check_full(void)
{
	int fd;

	fd = open("/dev/null", O_RDONLY);
	if (fd >= 0) {
		fail("Descriptor %d was allocated below a full RLIMIT_NOFILE", fd);
		close(fd);
		return -1;
	}

	if (errno != EMFILE) {
		fail("open() did not fail with EMFILE");
		return -1;
	}

	return 0;
}

int main(int argc, char **argv)
{
	struct rlimit lim = { .rlim_cur = NOFILE, .rlim_max = NOFILE }, trlim;
	struct rlimit flim = { .rlim_cur = FSIZE, .rlim_max = FSIZE }, tflim;
	struct stat st;
	int fd;

	test_init(argc, argv);

	if (fill_slots())
		return 1;

	if (setrlimit(RLIMIT_NOFILE, &lim)) {
		pr_perror("Can't set RLIMIT_NOFILE");
		return 1;
	}

	if (setrlimit(RLIMIT_FSIZE, &flim)) {
		pr_perror("Can't set RLIMIT_FSIZE");
		return 1;
	}

	if (check_full())
		return 1;

	test_daemon();
	test_waitsig();

	if (getrlimit(RLIMIT_NOFILE, &trlim) || getrlimit(RLIMIT_FSIZE, &tflim)) {
		fail("Can't get rlimits after restore");
		return 1;
	}

	if (trlim.rlim_cur != lim.rlim_cur || trlim.rlim_max != lim.rlim_max) {
		fail("RLIMIT_NOFILE changed to %lu/%lu", (unsigned long)trlim.rlim_cur, (unsigned long)trlim.rlim_max);
		return 1;
	}

	if (tflim.rlim_cur != flim.rlim_cur || tflim.rlim_max != flim.rlim_max) {
		fail("RLIMIT_FSIZE changed to %lu/%lu", (unsigned long)tflim.rlim_cur, (unsigned long)tflim.rlim_max);
		return 1;
	}

	for (fd = 0; fd < NOFILE; fd++) {
		if (fstat(fd, &st)) {
			fail("Descriptor %d is gone", fd);
			return 1;
		}
	}

	if (check_full())
		return 1;

	pass();
	return 0;
}
