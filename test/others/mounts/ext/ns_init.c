#define _GNU_SOURCE
#include <sched.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/mount.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <string.h>

static void sigh(int sig)
{
}

int main(int argc, char **argv)
{
	int start[2];
	char res;
	pid_t pid;

	/*
	 * Usage:
	 * run <pidfile> <root> <log-file-name> <file-to-check> <contents-to-check>
	 */

	if (getpid() == 1) {
		int fd;
		struct sigaction sa = {};
		sigset_t mask;

		if (setsid() == -1) {
			fprintf(stderr, "setsid: %m\n");
			return 1;
		}

		sa.sa_handler = sigh;
		sigaction(SIGTERM, &sa, NULL);

		if (chdir(argv[2]))
			return 1;

		fd = open(argv[3], O_WRONLY|O_CREAT|O_TRUNC|O_APPEND, 0600);
		if (fd < 0)
			return 1;

		dup2(fd, 1);
		dup2(fd, 2);
		close(fd);
		close(0);

		if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL)) {
			fprintf(stderr, "mount(/, S_REC | MS_PRIVATE)): %m");
			return 1;
		}

		mkdir("oldm");
		if (pivot_root(".", "./oldm") < 0)
			return 1;

		umount2("/oldm", MNT_DETACH);

		mkdir("/proc");
		if (mount("zdtm_proc", "/proc", "proc", 0, NULL)) {
			fprintf(stderr, "mount(/proc): %m");
			return 1;
		}

		sigemptyset(&mask);
		sigaddset(&mask, SIGTERM);
		sigprocmask(SIG_BLOCK, &mask, NULL);

		fd = atoi(argv[1]);
		write(fd, "!", 1);
		close(fd);

		sigemptyset(&mask);
		sigsuspend(&mask);

		printf("Woken UP\n");
		printf("Reading %s for [%s]\n", argv[4], argv[5]);
		{
			FILE *f;
			char buf[128];

			f = fopen(argv[4], "r");
			if (!f)
				perror("No file with message");
			else {
				memset(buf, 0, sizeof(buf));
				fgets(buf, sizeof(buf), f);
				fclose(f);
				printf("Got [%s]\n", buf);

				if (!strcmp(buf, argv[5]))
					printf("PASS\n");
			}
		}

		exit(0);
	}

	if (unshare(CLONE_NEWNS | CLONE_NEWPID))
		return 1;

	pipe(start);
	pid = fork();
	if (pid == 0) {
		char *nargv[7], aux[10];

		close(start[0]);
		sprintf(aux, "%d", start[1]);
		nargv[0] = argv[0];
		nargv[1] = aux;
		nargv[2] = argv[2];
		nargv[3] = argv[3];
		nargv[4] = argv[4];
		nargv[5] = argv[5];
		nargv[6] = NULL;

		execv(argv[0], nargv);
		exit(0);
	}

	close(start[1]);
	res = 'F';
	read(start[0], &res, 1);
	if (res != '!') {
		printf("Failed to start\n");
		return 1;
	}

	printf("Container w/ tests started\n");
	{
		FILE *pidf;
		pidf = fopen(argv[1], "w");
		fprintf(pidf, "%d", pid);
		fclose(pidf);
	}

	return 0;
}
