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

int main(int argc, char *argv[])
{
	int pipefd1[2];
	int pipefd2[2];
	pid_t pid;

	printf("%s pid %d\n", argv[0], getpid());

	if (pipe(pipefd1)) {
		perror("Can't create pipe1");
		return -1;
	}

	pid = fork();
	if (pid == -1) {
		printf("fork failed\n");
		return 1;
	} else if (pid == 0) {
		long buf;

		if (pipe(pipefd2)) {
			perror("Can't create pipe2");
			return -1;
		}

		pid = fork();
		if (pid == -1) {
			printf("fork failed\n");
			return 1;
		} else if (pid == 0) {
			while (1) {
				long buf;
				read(pipefd1[0], &buf, sizeof(buf));
				printf("pipe2-r: %08lx\n", buf);
				sleep(1);
			}
		}

		while (1) {
			read(pipefd1[0], &buf, sizeof(buf));
			printf("pipe1-r: %08lx\n", buf);
			printf("pipe2-w: %08lx\n", buf);
			write(pipefd2[1], &buf, sizeof(buf));
			sleep(1);
		}
	} else {
		long buf = 0;
		while (1) {
			printf("pipe1-w: %08lx\n", buf);
			write(pipefd1[1], &buf, sizeof(buf));
			sleep(1);
			buf++;
		}
	}

	return 0;
}
