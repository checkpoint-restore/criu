#include <stdio.h>
#include <stdlib.h>

#include <unistd.h>

#include <sys/types.h>
#include <signal.h>

static void forked_handler(int sig)
{
	printf("%d: %s\n", getpid(), __func__);
}

static void primary_handler(int sig)
{
	printf("%d: %s\n", getpid(), __func__);
}

int main(int argc, char *argv[])
{
	struct sigaction act;
	int pid;

	printf("%s pid %d\n", argv[0], getpid());

	pid = fork();
	if (pid < 0) {
		exit(-1);
	} else if (pid == 0) {
		act.sa_handler	= forked_handler;
		act.sa_flags	= 0;
		sigemptyset(&act.sa_mask);
		sigaction(SIGTSTP, &act, 0);

		while (1) {
			kill(getppid(), SIGTSTP);
			kill(getpid(), SIGTSTP);
			sleep(1);
		}

	} else {
		act.sa_handler	= primary_handler;
		act.sa_flags	= 0;
		sigemptyset(&act.sa_mask);
		sigaction(SIGTSTP, &act, 0);

		while (1) {
			sleep(1);
		}
	}

	return 0;
}
