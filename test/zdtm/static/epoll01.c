#include <unistd.h>

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/eventfd.h>
#include <sys/ioctl.h>
#include <sys/epoll.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>

#include "zdtmtst.h"

const char *test_doc = "Check another case of epoll: This adds three epoll "
		       "targets on tfd 702 and then adds two epoll targets "
		       "on tfd 701. This test is for off calculation in "
		       "dump_one_eventpoll, the reverse order makes qsort "
		       "to actually work.";
const char *test_author = "Pavel Tikhomirov <ptikhomirov@virtuozzo.com>";

int main(int argc, char *argv[])
{
	int epollfd;
	struct epoll_event ev;
	int i, ret;

	struct {
		int pipefd[2];
		int dupfd;
		bool close;
	} pipes[5] = {
		{ {}, 702, true }, { {}, 702, true }, { {}, 702, false }, { {}, 701, true }, { {}, 701, false },
	};

	test_init(argc, argv);

	epollfd = epoll_create(1);
	if (epollfd < 0) {
		pr_perror("epoll_create failed");
		exit(1);
	}

	memset(&ev, 0, sizeof(ev));
	ev.events = EPOLLIN | EPOLLOUT;

	for (i = 0; i < ARRAY_SIZE(pipes); i++) {
		int fd;

		if (pipe(pipes[i].pipefd)) {
			pr_err("Can't create pipe %d\n", i);
			exit(1);
		}

		ev.data.u64 = i;

		fd = dup2(pipes[i].pipefd[0], pipes[i].dupfd);
		if (fd < 0 || fd != pipes[i].dupfd) {
			pr_perror("Can't dup %d to %d", pipes[i].pipefd[0], pipes[i].dupfd);
			exit(1);
		}

		test_msg("epoll %d add %d dup'ed from %d\n", epollfd, fd, pipes[i].pipefd[0]);
		if (epoll_ctl(epollfd, EPOLL_CTL_ADD, fd, &ev)) {
			pr_perror("Can't add pipe %d", fd);
			close(fd);
			exit(1);
		}

		if (pipes[i].close) {
			close(fd);
			test_msg("epoll source %d closed\n", fd);
		}
	}

	test_daemon();
	test_waitsig();

	ret = 0;
	for (i = 0; i < ARRAY_SIZE(pipes); i++) {
		uint8_t cw = 1, cr;

		if (write(pipes[i].pipefd[1], &cw, sizeof(cw)) != sizeof(cw)) {
			pr_perror("Unable to write into a pipe");
			return 1;
		}

		if (epoll_wait(epollfd, &ev, 1, -1) != 1) {
			pr_perror("Unable to wait events");
			return 1;
		}

		if (ev.data.u64 != i) {
			pr_err("ev.fd=%d ev.data.u64=%#llx (%d expected)\n", ev.data.fd, (long long)ev.data.u64, i);
			ret |= 1;
		}

		if (read(pipes[i].pipefd[0], &cr, sizeof(cr)) != sizeof(cr)) {
			pr_perror("read");
			return 1;
		}
	}

	if (ret)
		return 1;

	pass();
	return 0;
}
