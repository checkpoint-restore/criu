#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <sys/prctl.h>
#include <sys/wait.h>

#include "zdtmtst.h"

const char *test_doc	= "Check that pdeath sig is preserved";
const char *test_author	= "Pavel Emelianov <xemul@parallels.com>";

static int sigrecvd = 0;
static void sigh(int s, siginfo_t *i, void *d)
{
	sigrecvd = 1;
}

#ifndef PR_SET_PDEATH_SIGNAL
#define PR_SET_PDEATH_SIGNAL 1
#endif

int main(int argc, char **argv)
{
	int pid, ret, pw[2], pr[2];

	test_init(argc, argv);

	/*
	 * Here's what will happen here:
	 *
	 *    me -(fork)-> P -(fork)-> C
	 *     |                       |
	 *     +-------------->-(pw)->-+
	 *     +-<-(pr)-<--------------+
	 *
	 * We wait for C to prepare himself via pr.
	 * After C/R we kill P and close pw to wake up
	 * C. The we wait for it to report back via pr
	 * which signals has he received.
	 */

	pipe(pw);
	pipe(pr);

	pid = fork();
	if (pid == 0) {
		pid = fork();
		if (pid == 0) {
			struct sigaction sa = {};
			/* C */
			close(pw[1]);
			close(pr[0]);
			sa.sa_sigaction = sigh;
			ret = sigaction(SIGUSR1, &sa, NULL);
			if (ret == 0)
				ret = prctl(PR_SET_PDEATH_SIGNAL, SIGUSR1, 0, 0, 0);
			write(pr[1], &ret, sizeof(ret));
			read(pw[0], &ret, sizeof(ret));
			write(pr[1], &sigrecvd, sizeof(sigrecvd));
		} else {
			/* P, pid == C */
			close(pw[0]);
			close(pw[1]);
			close(pr[0]);
			close(pr[1]);

			/* Just hang */
			waitpid(pid, NULL, 0);
		}

		exit(0);
	}

	/* me, pid == P */
	close(pw[0]);
	close(pr[1]);

	ret = -1;
	read(pr[0], &ret, sizeof(ret));
	if (ret != 0) {
		err("C start error\n");
		goto out;
	}

	/*
	 * P didn't have time to close his pipes?
	 * That's OK, CRIU should C/R these knots.
	 */

	test_daemon();
	test_waitsig();

out:
	kill(pid, SIGKILL);
	waitpid(pid, NULL, 0);
	close(pw[1]);

	if (ret == 0) {
		read(pr[0], &ret, sizeof(ret));
		if (ret != 1)
			fail("USR1 isn't delivered");
		else
			pass();
	}

	return 0;
}
