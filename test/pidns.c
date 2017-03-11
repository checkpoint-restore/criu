#include <sched.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/mount.h>
#include <unistd.h>

int main(int argc, char **argv)
{
	pid_t pid;
	int status;

	/*
	 * pidns is used to avoid conflicts
	 * mntns is used to mount /proc
	 * net is used to avoid conflicts of parasite sockets
	 */
	if (unshare(CLONE_NEWNS | CLONE_NEWPID))
		return 1;
	pid = fork();
	if (pid == 0) {
		int ret = 0, p;
		if (mount(NULL, "/", NULL, MS_REC | MS_SLAVE, NULL)) {
			fprintf(stderr, "mount(/, S_REC | MS_SLAVE)): %m");
			return 1;
		}
		umount2("/proc", MNT_DETACH);
		if (mount("zdtm_proc", "/proc", "proc", 0, NULL)) {
			fprintf(stderr, "mount(/proc): %m");
			return 1;
		}
		pid = fork();
		if (pid < 0)
			return 1;
		if (pid == 0) {
			execvp(argv[1], argv + 1);
			fprintf(stderr, "execve: %m");
			return 1;
		}
		while (1) {

			p = waitpid(-1, &status, 0);
			if (p == pid)
				ret = status != 0;
			if (p < 0)
				break;
		}
		return ret;
	}

	if (waitpid(pid, &status, 0) != pid) {
		fprintf(stderr, "waitpid: %m");
		return 1;
	}

	return status != 0;
}
