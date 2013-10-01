#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>

#include "zdtmtst.h"

const char *test_doc	= "Check, that stopped tasts are restored correctly";
const char *test_author	= "Andrew Vagin <avagin@parallels.com>";

int main(int argc, char **argv)
{
	pid_t pid;
	int p[2], ret, status;

	test_init(argc, argv);

	if (pipe(p)) {
		err("Unable to create pipe");
		return 1;
	}

	pid = test_fork();
	if (pid < 0)
		return -1;
	else if (pid == 0) {
		char c;

		close(p[1]);
		ret = read(p[0], &c, 1);
		if (ret != 1) {
			err("Unable to read: %d", ret);
			return 1;
		}

		ret = read(p[0], &c, 1);
		if (ret != 0) {
			err("Unable to read: %d", ret);
			return 1;
		}

		return 0;
	}
	close(p[0]);

	kill(pid, SIGSTOP);
	write(p[1], "0", 1);

	test_daemon();
	test_waitsig();

	kill(pid, SIGCONT);
	if (waitpid(pid, &status, WCONTINUED) == -1) {
		err("Unable to wait child");
		goto out;
	}

	if (WIFCONTINUED(status))
		pass();
	else
		fail("The process doesn't continue");
out:
	close(p[1]);
	waitpid(pid, &status, 0);

	return 0;
}
