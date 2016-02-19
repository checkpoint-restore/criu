#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <string.h>
#include <errno.h>
#include <sys/time.h>
#include <time.h>
#include <sys/epoll.h>

#include "zdtmtst.h"

const char *test_doc	= "migrate application using epoll";

#define MAX_SCALE	128

enum child_exit_codes {
	SUCCESS = 0,
	GETTIMEOFDAYERROR,
	WRITEERROR,

	MAX_EXIT_CODE
};

static char *child_fail_reason[] = {
	"Success",
	"Can't get time",
	"Can't write"
};

int scale = 13;
TEST_OPTION(scale, int, "How many children should perform testing", 0);

static int pids[MAX_SCALE];
static int fds[MAX_SCALE][2];
static volatile int stop = 0;

static void killall(void)
{
	int i;

	for (i = 0; i < scale; i++) {
		close(fds[i][0]);
		close(fds[i][1]);
		kill(pids[i], SIGUSR2);
	}
}

static void do_stop(int sig)
{
	stop = 1;
}

static void run_child(int num)
{
	int fd = fds[num][1];
	uint32_t crc = ~0;
	size_t buf_size=512;
	uint8_t buf[buf_size];
	struct timeval tv;
	struct timespec ts;
	int rv;

	close(fds[num][0]);

	datagen(buf, sizeof(buf), &crc);

	if (gettimeofday(&tv, NULL) < 0) {
		rv = GETTIMEOFDAYERROR;
		goto out;
	}

	srand(tv.tv_sec + tv.tv_usec);

	ts.tv_sec = 0;
	while (!stop) {
		ts.tv_nsec = rand() % 999999999;
		nanosleep(&ts, &ts);
		if (write(fd, buf, buf_size) < 0 &&
			(!stop /* signal SIGUSR2 NOT received */ ||
				(errno != EINTR && errno != EPIPE))) {
			fail("child write: %m\n");
			rv = WRITEERROR;
			goto out;
		}
	}
	rv = SUCCESS;
out:	close(fds[num][1]);
	exit(rv);
}

int main(int argc, char **argv)
{
	int rv, i;
	int counter = 0;
	int efd;
	size_t buf_size=512;
	char buf[buf_size];
	struct epoll_event event = {
		.events = EPOLLIN
	}, *events;

	test_init(argc, argv);

	if (scale > MAX_SCALE) {
		pr_err("Too many children specified\n");
		exit(1);
	}

	if (signal(SIGUSR2, do_stop) == SIG_ERR) {
		pr_perror("Can't setup signal handler");
		exit(1);
	}

	if ((efd = epoll_create(scale)) < 0) {
		pr_perror("Can't create epoll");
		exit(1);
	}

	for (i = 0; i < scale; i++) {
		if (pipe(fds[i]) < 0) {
			pr_perror("Can't create pipe[%d]", i);
			killall();
			exit(1);
		}
		if (fcntl(fds[i][0], F_SETFL, O_NONBLOCK) < 0) {
			pr_perror("Can't set O_NONBLOCK flag on fd[%d]", i);
			killall();
			exit(1);
		}
		event.data.fd = fds[i][0];
		if (epoll_ctl(efd, EPOLL_CTL_ADD, fds[i][0], &event) < 0) {
			pr_perror("Can't add fd[%d]", i);
			killall();
			exit(1);
		}

		if ((rv = test_fork()) < 0) {
			pr_perror("Can't fork[%d]", i);
			killall();
			exit(1);
		}
		if (rv == 0)
			run_child(i);
		close(fds[i][1]);
		pids[i] = rv;
	}

	if ((events = (struct epoll_event*) malloc (sizeof(struct epoll_event)*scale)) == NULL) {
		pr_perror("Can't allocate memory");
		killall();
		exit(1);
	}

	test_daemon();

	while (test_go()) {
		if ((rv = epoll_wait(efd, events, scale, rand() % 999)) < 0 && errno != EINTR) {
			pr_perror("epoll_wait error");
			killall();
			exit(1);
		}
		for (i = 0; i < rv; i++) {
			while (read(events[i].data.fd, buf, buf_size) > 0);
			if (errno != EAGAIN && errno != 0 && errno) {
				pr_perror("read error");
				killall();
				exit(1);
			}
		}
	}

	test_waitsig();

	killall();
	for (i = 0; i < scale; i++) {
		if (waitpid(pids[i], &rv, 0) < 0) {
			fail("waitpid error: %m\n");
			counter++;
			continue;
		}
		else {
			rv = WEXITSTATUS(rv);
			if (rv < MAX_EXIT_CODE && rv > SUCCESS) {
				fail("Child failed: %s (%d)\n",
						child_fail_reason[rv], rv);
				counter++;
			} else if (rv != SUCCESS) {
				fail("Unknown exitcode from child: %d\n", rv);
				counter++;
			}
		}
	}
	if (counter == 0)
		pass();
	return 0;
}
