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
	if (unshare(CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWNET | CLONE_NEWIPC))
		return 1;
	pid = fork();
	if (pid == 0) {
		if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL)) {
			fprintf(stderr, "mount(/, S_REC | MS_PRIVATE)): %m");
			return 1;
		}
		umount2("/proc", MNT_DETACH);
		umount2("/dev/pts", MNT_DETACH);
		if (mount("zdtm_proc", "/proc", "proc", 0, NULL)) {
			fprintf(stderr, "mount(/proc): %m");
			return 1;
		}
		if (mount("zdtm_devpts", "/dev/pts", "devpts", 0,
					"newinstance,ptmxmode=0666")) {
			fprintf(stderr, "mount(pts): %m");
			return 1;
		}
		if (mount("zdtm_binfmt", "/proc/sys/fs/binfmt_misc", "binfmt_misc", 0,
					NULL)) {
			fprintf(stderr, "mount(binfmt_misc): %m");
			return 1;
		}
		if (mount("/dev/pts/ptmx", "/dev/ptmx", NULL, MS_BIND, NULL)) {
			fprintf(stderr, "mount(ptmx): %m");
			return 1;
		}
		if (system("ip link set up dev lo"))
			return 1;
		execv(argv[1], argv + 1);
		fprintf(stderr, "execve: %m");
		return 1;
	}

	if (waitpid(pid, &status, 0) != pid) {
		fprintf(stderr, "waitpid: %m");
		return 1;
	}

	if (WIFEXITED(status))
		return WEXITSTATUS(status);
	else if (WIFSIGNALED(status))
		kill(getpid(), WTERMSIG(status));
	else
		fprintf(stderr, "Unexpected exit status: %x\n", status);

	return 1;
}
