#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <string.h>

#include "zdtmtst.h"

const char *test_doc	= "See if we can wait() for a zombified child after migration";
const char *test_author	= "Roman Kagan <rkagan@parallels.com>";

int main(int argc, char ** argv)
{
	int ret;
	pid_t pid;

	test_init(argc, argv);

	pid = fork();
	if (pid < 0) {
		err("fork failed: %m\n");
		exit(1);
	}

	if (pid == 0)
		_exit(0);

	test_daemon();
	test_waitsig();

	if (wait(&ret) != pid) {
		fail("wait() returned wrong pid: %m\n");
		exit(1);
	}

	if (WIFEXITED(ret)) {
		ret = WEXITSTATUS(ret);
		if (ret) {
			fail("child exited with nonzero code %d (%s)\n", ret, strerror(ret));
			exit(1);
		}
	}
	if (WIFSIGNALED(ret)) {
		fail("child exited on unexpected signal %d\n", WTERMSIG(ret));
		exit(1);
	}

	pass();
	return 0;
}
