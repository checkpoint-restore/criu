#define _GNU_SOURCE         /* See feature_test_macros(7) */
#include <unistd.h>

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <utime.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/socket.h>

#include "zdtmtst.h"

#ifndef F_SETSIG
#define F_SETSIG	10	/* for sockets. */
#define F_GETSIG	11	/* for sockets. */
#endif

const char *test_doc	= "Check for signal delivery for file owners";
const char *test_author	= "Cyrill Gorcunov <gorcunov@openvz.org>";

static int received_io;

#define MAP(map, i)		(((int *)map)[i])
#define MAP_SYNC(map)		MAP(map, 0)
#define MAP_PID_PIPE0(map)	MAP(map, 1)
#define MAP_PID_PIPE1(map)	MAP(map, 2)
#define MAP_PID_SOK(map)	MAP(map, 3)

#define SK_DATA "packet"

static void signal_handler_io(int status)
{
	received_io++;
}

int main(int argc, char ** argv)
{
	pid_t pid, ppid;
	struct sigaction saio;
	int status;
	int pipes[2];
	void *map;
	uid_t ruid;
	uid_t euid;
	uid_t suid;

	int ssk_pair[2];
	char buf[64];

	test_init(argc, argv);

	if (getresuid(&ruid, &euid, &suid)) {
		fail("getresuid failed");
		exit(1);
	}

	map = mmap(NULL, 1024, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (map == MAP_FAILED) {
		fail("Can't map");
		exit(1);
	}

	if (pipe(pipes)) {
		err("Can't create pipes: %m\n");
		exit(1);
	}

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, ssk_pair) == -1) {
		fail("socketpair\n");
		exit(1);
	}

	memset(&saio, 0, sizeof(saio));
	saio.sa_handler = (sig_t)signal_handler_io;
	sigaction(SIGIO, &saio, 0);

	if (setresuid(-1, 1, -1)) {
		fail("setresuid failed");
		exit(1);
	}

	fcntl(pipes[0], F_SETOWN, getpid());
	fcntl(pipes[1], F_SETOWN, getpid());

	test_msg("main owner pipes[0]: %d\n", fcntl(pipes[0], F_GETOWN));

	fcntl(pipes[0], F_SETSIG, SIGIO);
	fcntl(pipes[1], F_SETSIG, SIGIO);

	fcntl(pipes[0], F_SETFL, fcntl(pipes[0], F_GETFL) | O_NONBLOCK | O_ASYNC);
	fcntl(pipes[1], F_SETFL, fcntl(pipes[1], F_GETFL) | O_NONBLOCK | O_ASYNC);

	fcntl(ssk_pair[0], F_SETOWN, getpid());
	fcntl(ssk_pair[0], F_SETSIG, SIGIO);
	fcntl(ssk_pair[0], F_SETFL, fcntl(ssk_pair[0], F_GETFL) | O_NONBLOCK | O_ASYNC);
	test_msg("main owner ssk_pair[0]: %d\n", fcntl(ssk_pair[0], F_GETOWN));

	write(ssk_pair[0], SK_DATA, sizeof(SK_DATA));
	read(ssk_pair[1], &buf, sizeof(buf));
	if (strcmp(buf, SK_DATA)) {
		fail("data corrupted\n");
		exit(1);
	}
	test_msg("stream            : '%s'\n", buf);

	if (setresuid(-1, euid, -1)) {
		fail("setresuid failed");
		exit(1);
	}

	ppid = getpid();

	pid = test_fork();

	if (pid < 0) {
		err("can't fork %m");
		exit(1);
	}

	MAP_SYNC(map) = 0;

	if (pid == 0) {
		int v = 1;

		write(pipes[1], &v, sizeof(v));
		read(pipes[0], &v, sizeof(v));

		MAP_SYNC(map) = 1;

		while (MAP_SYNC(map) != 3)
			sleep(1);

		fcntl(pipes[1], F_SETOWN, getpid());

		write(pipes[1], &v, sizeof(v));
		read(pipes[0], &v, sizeof(v));

		write(ssk_pair[0], SK_DATA, sizeof(SK_DATA));
		read(ssk_pair[1], &buf, sizeof(buf));
		if (strcmp(buf, SK_DATA)) {
			fail("data corrupted\n");
			exit(1);
		}
		test_msg("stream            : '%s'\n", buf);

		MAP_PID_PIPE0(map) = fcntl(pipes[0], F_GETOWN);
		MAP_PID_PIPE1(map) = fcntl(pipes[1], F_GETOWN);
		MAP_PID_SOK(map) = fcntl(ssk_pair[0], F_GETOWN);

		exit(0);
	}

	while (MAP_SYNC(map) != 1)
		sleep(1);

	test_daemon();
	test_waitsig();

	MAP_SYNC(map) = 3;

	waitpid(pid, &status, P_ALL);

	if (received_io < 1		||
	    MAP_PID_PIPE0(map) != ppid	||
	    MAP_PID_PIPE1(map) != pid	||
	    MAP_PID_SOK(map)   != ppid) {
		fail("received_io = %d ppid: %d  MAP_PID_PIPE0(map): %d "
		     "MAP_PID_PIPE1(map): %d MAP_PID_SOK(map): %d\n",
		     received_io, ppid, MAP_PID_PIPE0(map),
		     MAP_PID_PIPE1(map), MAP_PID_SOK(map));
		exit(1);
	}

	pass();
	return 0;
}
