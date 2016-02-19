#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <string.h>

#include "zdtmtst.h"

const char *test_doc	= "Block migration by a pending (non-exec()-ed) vfork()";
const char *test_author	= "Pavel Emelianov <xemul@sw.ru>";

int main(int argc, char ** argv)
{
	int ret = 0;
	pid_t pid;

	test_init(argc, argv);

	/* vfork() won't let us control the test, so fork() first, and vfork()
	 * in the child */
	pid = fork();
	if (pid < 0) {
		pr_err("fork failed: %m");
		exit(1);
	}

	if (pid == 0) {
		int ret2;

		pid = vfork();
		if (pid < 0)
			ret = errno;

		/* wait for signal in _both_ branches */
		test_waitsig();

		/* vforked guy shouldn't return, hence we exec() */
		if (pid == 0)
			execlp("/bin/true", "true", NULL);

		if (wait(&ret2) != pid)
			ret = errno;

		_exit(ret);
	}

	test_daemon();
	test_waitsig();

	/* signal the whole process group, because our child is suspended until
	 * the grand-child has exec()-ed, but we don't know the pid of the
	 * latter */
	if (kill(0, SIGTERM)) {
		fail("terminating the children failed: %m");
		exit(1);
	}

	if (wait(&ret) != pid) {
		fail("wait() returned wrong pid: %m");
		exit(1);
	}

	if (WIFEXITED(ret)) {
		ret = WEXITSTATUS(ret);
		if (ret) {
			fail("child exited with nonzero code %d (%s)", ret, strerror(ret));
			exit(1);
		}
	}
	if (WIFSIGNALED(ret)) {
		fail("child exited on unexpected signal %d", WTERMSIG(ret));
		exit(1);
	}

	pass();
	return 0;
}
