#include <unistd.h>
#include <stdlib.h>
#include <stdbool.h>
#include <signal.h>
#include <stddef.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/prctl.h>

#include "zdtmtst.h"

const char *test_doc = "Check that a zombie with a helper parent is restored";
const char *test_author = "Tycho Andersen <tycho.andersen@canonical.com>";

void setsid_and_fork(int sk)
{
	siginfo_t infop;
	pid_t zombie;

	setsid();

	zombie = fork();
	if (zombie < 0) {
		fail("fork");
		exit(1);
	}

	if (zombie == 0)
		exit(0);

	if (waitid(P_PID, zombie, &infop, WNOWAIT | WEXITED) < 0) {
		fail("waitid");
		exit(1);
	}

	if (write(sk, &zombie, sizeof(zombie)) != sizeof(zombie)) {
		fail("write");
		exit(1);
	}

	close(sk);

	exit(0);
}

int main(int argc, char **argv)
{
	pid_t pid, zombie;
	int status, sk_pair[2];

	if (setenv("ZDTM_NOREAP", "1", 1) < 0) {
		fail("setenv");
		return 1;
	}

	test_init(argc, argv);

	if (socketpair(PF_LOCAL, SOCK_STREAM, 0, sk_pair)) {
		pr_perror("socketpair");
		return 1;
	}

	pid = fork();
	if (pid < 0) {
		fail("fork");
		return 1;
	}

	if (pid == 0) {
		close(sk_pair[0]);
		setsid_and_fork(sk_pair[1]);
	}

	close(sk_pair[1]);

	if (read(sk_pair[0], &zombie, sizeof(zombie)) != sizeof(zombie)) {
		fail("read");
		kill(pid, SIGKILL);
		return 1;
	}

	if (waitpid(pid, &status, 0) < 0) {
		fail("waitpid");
		return 1;
	}

	if (!WIFEXITED(status) || WEXITSTATUS(status)) {
		fail("setsid_and_fork");
		return 1;
	}

	if (kill(zombie, 0) < 0) {
		fail("zombie already dead?");
		return 1;
	}

	test_daemon();
	test_waitsig();

	/* XXX: we don't restore zombies with the right uid right now; they're all root */
	if (kill(zombie, 0) < 0 && errno != EPERM) {
		fail("zombie didn't survive restore");
		return 1;
	}

	pass();
	return 0;
}
