#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>
#include <poll.h>

#include "zdtmtst.h"

static int pidfd_open(pid_t pid, unsigned int flags)
{
	return syscall(SYS_pidfd_open, pid, flags);
}

const char *test_doc = "Pidfd ";
const char *test_author = "Suraj Shirvankar <surajshirvankar@gmail.com>";

int main(int argc, char **argv)
{
	int pidfd, errcode = 42;
	int status;
	int ret;
	struct pollfd pollfd;

	test_init(argc, argv);

	pidfd = pidfd_open(1, 0);
	if (pidfd == -1) {
		perror("Couldnt open pidfd");
		exit(1);
	}

	test_daemon();
	test_waitsig();

	pollfd.fd = pidfd;
	pollfd.events = POLLIN;

	ret = poll(&pollfd, 1, -1);
	if (ret == -1) {
		pr_perror("Poll error");
		fail();
	}

	if (pollfd.revents & POLLIN) {
		if (read(pidfd, &status, sizeof(status)) != sizeof(status)) {
			fail("pidfd read error");
		}
		if (status == errcode) {
			printf("Status code is %d", status);
			pass();
		} else {
			fail("Exit code mismatch");
		}
	}

	return 0;
}
