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

const char *test_doc	= "Check for signal delivery on file owners";
const char *test_author	= "Cyrill Gorcunov <gorcunov@openvz.org>";

struct params {
	int	sigio;
	int	pipe_flags[2];
	int	pipe_pid[2];
	int	pipe_sig[2];
} *shared;

static void signal_handler_io(int status)
{
	shared->sigio++;
}

static void fill_pipe_params(struct params *p, int *pipes)
{
	p->pipe_flags[0] = fcntl(pipes[0], F_GETFL);
	p->pipe_flags[1] = fcntl(pipes[1], F_GETFL);

	/*
	 * The kernel's O_LARGEFILE set automatically
	 * on open() in x86-64, so unmask it explicitly
	 * we restore pipes via open call while the former
	 * pipes are created with pipe() and have no O_LARGEFILE
	 * set.
	 */
	p->pipe_flags[0] &= ~00100000;
	p->pipe_flags[1] &= ~00100000;

	test_msg("pipe_flags0 %08o\n", p->pipe_flags[0]);
	test_msg("pipe_flags1 %08o\n", p->pipe_flags[1]);

	p->pipe_pid[0] = fcntl(pipes[0], F_GETOWN);
	p->pipe_pid[1] = fcntl(pipes[1], F_GETOWN);

	p->pipe_sig[0] = fcntl(pipes[0], F_GETSIG);
	p->pipe_sig[1] = fcntl(pipes[1], F_GETSIG);
}

static int cmp_pipe_params(struct params *p1, struct params *p2)
{
	int i;

	for (i = 0; i < 2; i++) {
		if (p1->pipe_flags[i] != p2->pipe_flags[i]) {
			fail("pipe flags failed [%d] expected %08o got %08o\n",
			     i, p1->pipe_flags[i], p2->pipe_flags[i]);
			return -1;
		}
		if (p1->pipe_pid[i] != p2->pipe_pid[i]) {
			fail("pipe pid failed [%d] expected %d got %d\n",
			     i, p1->pipe_pid[i], p2->pipe_pid[i]);
			return -1;
		}
		if (p1->pipe_sig[i] != p2->pipe_sig[i]) {
			fail("pipe sig failed [%d] expected %d got %d\n",
			     i, p1->pipe_sig[i], p2->pipe_sig[i]);
			return -1;
		}
	}

	return 0;
}

int main(int argc, char *argv[])
{
	struct sigaction saio = { };
	struct params obtained = { };
	uid_t ruid, euid, suid;
	int status, pipes[2];
	pid_t pid;

	test_init(argc, argv);

	shared = (void *)mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if ((void *)shared == MAP_FAILED) {
		fail("mmap failed");
		exit(1);
	}

	if (getresuid(&ruid, &euid, &suid)) {
		fail("getresuid failed\n");
		exit(1);
	}

	if (pipe(pipes)) {
		err("Can't create pipe: %m\n");
		exit(1);
	}

	saio.sa_handler	= (sig_t)signal_handler_io;
	saio.sa_flags	= SA_RESTART;
	if (sigaction(SIGIO, &saio, 0)) {
		fail("sigaction failed\n");
		exit(1);
	}

	if (setresuid(-1, 1, -1)) {
		fail("setresuid failed\n");
		exit(1);
	}

	if (fcntl(pipes[0], F_SETOWN, getpid())					||
	    fcntl(pipes[1], F_SETOWN, getpid())					||
	    fcntl(pipes[0], F_SETSIG, SIGIO)					||
	    fcntl(pipes[1], F_SETSIG, SIGIO)					||
	    fcntl(pipes[0], F_SETFL, fcntl(pipes[0], F_GETFL) | O_ASYNC)	||
	    fcntl(pipes[1], F_SETFL, fcntl(pipes[1], F_GETFL) | O_ASYNC)) {
		fail("fcntl failed\n");
		exit(1);
	}

	asm volatile ("" :::);

	fill_pipe_params(shared, pipes);

	if (setresuid(-1, euid, -1)) {
		fail("setresuid failed\n");
		exit(1);
	}

	pid = test_fork();
	if (pid < 0) {
		err("can't fork %m");
		exit(1);
	}

	if (pid == 0) {
		struct params p = { };

		test_waitsig();

		fcntl(pipes[1], F_SETOWN, getpid());
		fill_pipe_params(&p, pipes);

		if (write(pipes[1], &p, sizeof(p)) != sizeof(p)) {
			fail("write failed\n");
			exit(1);
		}

		exit(0);
	}

	test_daemon();
	test_waitsig();
	kill(pid, SIGTERM);

	if (waitpid(pid, &status, P_ALL) == -1) {
		fail("waitpid failed\n");
		exit(1);
	}

	if (read(pipes[0], &obtained, sizeof(obtained)) != sizeof(obtained)) {
		fail("read failed\n");
		exit(1);
	}

	if (shared->sigio < 1) {
		fail("shared->sigio = %d (> 0 expected)\n", shared->sigio);
		exit(1);
	}

	shared->pipe_pid[1] = pid;

	if (cmp_pipe_params(shared, &obtained)) {
		fail("params comparison failed\n");
		exit(1);
	}

	pass();
	return 0;
}
