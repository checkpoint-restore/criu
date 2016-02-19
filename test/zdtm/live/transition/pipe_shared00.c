#include <stdio.h>
#include <signal.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <limits.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/wait.h>

#include "zdtmtst.h"

const char *test_doc	= "Multi-process pipe split";
const char *test_author	= "Pavel Emelianov <xemul@parallels.com>";

#define PROCS_DEF	4
#define PROCS_MAX	64
unsigned int num_procs = PROCS_DEF;
TEST_OPTION(num_procs, uint, "# processes to create "
	    "(default " __stringify(PROCS_DEF)
	    ", max " __stringify(PROCS_MAX) ")", 0);

volatile sig_atomic_t num_exited = 0;
void inc_num_exited(int signo)
{
	num_exited++;
}

#define SND_CHR 'y'

int main(int argc, char **argv)
{
	int ret = 0;
	pid_t pid;
	int i;
	uint8_t buf[PIPE_BUF * 100];
	int pipes[2];

	test_init(argc, argv);

	if (num_procs > PROCS_MAX) {
		pr_err("%d processes is too many: max = %d\n", num_procs, PROCS_MAX);
		exit(1);
	}

	if (pipe(pipes)) {
		pr_perror("Can't create pipes");
		exit(1);
	}

	if (signal(SIGCHLD, inc_num_exited) == SIG_ERR) {
		pr_perror("can't set SIGCHLD handler");
		exit(1);
	}

	for (i = 1; i < num_procs; i++) {	/* i = 0 - parent */
		pid = test_fork();
		if (pid < 0) {
			pr_perror("can't fork");
			kill(0, SIGKILL);
			exit(1);
		}

		if (pid == 0) {
			close(pipes[1]);

			while (test_go()) {
				int rlen = read(pipes[0], buf, sizeof(buf));
				if (rlen == 0)
					break;
				else if (rlen < 0) {
					ret = errno;	/* pass errno as exit code to the parent */
					break;
				}

				for (i = 0; i < rlen && buf[i] == SND_CHR; i++)
					;
				if (i < rlen) {
					ret = EILSEQ;
					break;
				}
			}

			test_waitsig();	/* even if failed, wait for migration to complete */

			close(pipes[0]);
			exit(ret);
		}
	}

	close(pipes[0]);

	if (num_exited) {
		pr_err("Some children died unexpectedly\n");
		kill(0, SIGKILL);
		exit(1);
	}

	test_daemon();

	memset(buf, SND_CHR, sizeof(buf));
	while(test_go())
		if (write(pipes[1], buf, sizeof(buf)) < 0 &&
		    (errno != EINTR || test_go())) {	/* only SIGTERM may stop us */
			fail("write failed: %m\n");
			ret = 1;
			break;
		}
	close(pipes[1]);

	test_waitsig();	/* even if failed, wait for migration to complete */

	if (kill(0, SIGTERM)) {
		fail("failed to send SIGTERM to my process group: %m\n");
		goto out;	/* shouldn't wait() in this case */
	}

	for (i = 1; i < num_procs; i++) {	/* i = 0 - parent */
		int chret;
		if (wait(&chret) < 0) {
			fail("can't wait for a child: %m\n");
			ret = 1;
			continue;
		}

		chret = WEXITSTATUS(chret);
		if (chret) {
			fail("child exited with non-zero code %d (%s)\n",
			     chret, strerror(chret));
			ret = 1;
			continue;
		}
	}

	if (!ret)
		pass();

out:
	return 0;
}
