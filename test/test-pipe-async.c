#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>

#include <sys/wait.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>

#include <sched.h>

static void *map;

int main(int argc, char *argv[])
{
	int pipefd[2];
	pid_t pid;

	printf("%s pid %d\n", argv[0], getpid());

	if (pipe(pipefd)) {
		perror("Can't create pipe");
		return -1;
	}

	pid = fork();
	if (pid == -1) {
		printf("fork failed\n");
		return 1;
	} else if (pid == 0) {
		long buf;
		while (read(pipefd[0], &buf, sizeof(buf)) > 0) {
			printf("pipe-r: %08lx\n", buf);
			sleep(2);
		}
	} else {
		long buf = 0;
		while (1) {
			printf("pipe-w: %08lx\n", buf);
			write(pipefd[1], &buf, sizeof(buf));
			sleep(1);
			buf++;
		}
	}

	return 0;
}
