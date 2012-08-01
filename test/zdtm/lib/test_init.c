#define _GNU_SOURCE
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <signal.h>
#include <sched.h>
#include <errno.h>
#include <sys/mman.h>
#include <linux/limits.h>
#include <string.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <sys/param.h>
#include <sys/mount.h>
#include <sys/stat.h>

#define STACK_SIZE	(8 * 4096)
#ifndef CLONE_NEWPID
/* CLONE_NEWPID since Linux 2.6.24 */
#define CLONE_NEWPID          0x20000000
#endif

static int sig_received;
static char dir[PATH_MAX];
static char name[PATH_MAX];
static char pidfile[PATH_MAX];
int status_pipe[2];

static void sig_hand(int signo)
{
	int status, len = 0;
	pid_t pid;
	char buf[128] = "";

	if (signo == SIGTERM) {
		sig_received = signo;
		len = snprintf(buf, sizeof(buf), "Time to stop and check\n");
		goto write_out;
	}

	while (1) {
		pid = waitpid(-1, &status, WNOHANG);
		if (pid == 0)
			return;
		if (pid == -1) {
			if (errno == ECHILD) {
				if (sig_received)
					return;
				sig_received = signo;
				len = snprintf(buf, sizeof(buf),
						"All test processes exited\n");
			} else {
				len = snprintf(buf, sizeof(buf),
						"wait() failed: %m\n");
			}
				goto write_out;
		}
		if (status)
			fprintf(stderr, "%d return %d\n", pid, status);
	}

	return;
write_out:
	/* fprintf can't be used in a sighandler due to glibc locks */
	write(STDERR_FILENO, buf, MAX(len, sizeof(buf)));
}

void test_waitsig(void)
{
	sigset_t mask, oldmask;

	/* Set up the mask of signals to temporarily block. */
	sigemptyset(&mask);
	sigaddset(&mask, SIGTERM);
	sigaddset(&mask, SIGCHLD);

	/* Wait for a signal to arrive. */
	sigprocmask(SIG_BLOCK, &mask, &oldmask);
	while (!sig_received)
		sigsuspend (&oldmask);
	sigprocmask (SIG_UNBLOCK, &mask, NULL);

	sig_received = 0;
}

static int prepare_mntns()
{
	FILE *f;
	unsigned fs_cnt, fs_cnt_last = 0;
	char buf[1024];

again:
	fs_cnt = 0;
	f = fopen("/proc/self/mountinfo", "r");
	if (!f) {
		fprintf(stderr, "Can't open mountinfo");
		return -1;
	}

	while (fgets(buf, sizeof(buf), f) != NULL) {
		char *mp = buf, *end;

		mp = strchr(mp, ' ') + 1;
		mp = strchr(mp, ' ') + 1;
		mp = strchr(mp, ' ') + 1;
		mp = strchr(mp, ' ') + 1;
		end = strchr(mp, ' ');
		*end = '\0';

		if (!strcmp(mp, "/"))
			continue;
		if (!strcmp(mp, "/proc"))
			continue;

		umount(mp);
		fs_cnt++;
	}

	fclose(f);

	if (fs_cnt == 0)
		goto done;

	if (fs_cnt != fs_cnt_last) {
		fs_cnt_last = fs_cnt;
		goto again;
	}

	fprintf(stderr, "Can't umount all the filesystems");
	return -1;
done:
	mknod("/dev/null", 0777 | S_IFCHR, makedev(1, 3));
	return 0;
}

int fn(void *_arg)
{
	struct sigaction sa = {
		.sa_handler	= sig_hand,
		.sa_flags	= SA_RESTART,
	};
	char cmd[256];
	int ret;

	close(status_pipe[0]);

	if (prepare_mntns())
		return 1;

	ret = fcntl(status_pipe[1], F_SETFD, FD_CLOEXEC);
	if (ret == -1) {
		fprintf(stderr, "fcntl failed %m\n");
		exit(1);
	}

	sigemptyset(&sa.sa_mask);
	sigaddset(&sa.sa_mask, SIGTERM);
	sigaddset(&sa.sa_mask, SIGCHLD);

	if (sigaction(SIGTERM, &sa, NULL)) {
		fprintf(stderr, "Can't set SIGTERM handler: %m\n");
		exit(1);
	}
	if (sigaction(SIGCHLD, &sa, NULL)) {
		fprintf(stderr, "Can't set SIGCHLD handler: %m\n");
		exit(1);
	}

	/* Start test */
	snprintf(cmd, sizeof(cmd), "make -C %s %s.pid", dir, name);
	ret = system(cmd);

	/* Daemonize */
	write(status_pipe[1], &ret, sizeof(ret));
	close(status_pipe[1]);
	if (ret)
		return ret;

	/* suspend/resume */
	test_waitsig();

	/* Stop test */
	snprintf(cmd, sizeof(cmd), "make -C %s %s.out", dir, name);
	ret = system(cmd);
	if (ret)
		return ret;

	ret = 0;
	while (ret != -1)
		ret = wait(NULL);

	return 0;
}

int main(int argc, char *argv[])
{
	void *stack;
	pid_t pid;
	int ret, status, fd;

	if (argc < 4)
		exit(1);

	strcpy(dir, argv[1]);
	strcpy(name, argv[2]);
	strcpy(pidfile, argv[3]);

	stack = mmap(NULL, STACK_SIZE, PROT_WRITE | PROT_READ,
			MAP_PRIVATE | MAP_GROWSDOWN | MAP_ANONYMOUS, -1, 0);
	if (stack == MAP_FAILED) {
		fprintf(stderr, "Can't map stack %m\n");
		exit(1);
	}
	ret = pipe(status_pipe);
	if (ret) {
		fprintf(stderr, "Pipe() failed %m\n");
		exit(1);
	}
	pid = clone(fn, stack + STACK_SIZE, CLONE_NEWPID | CLONE_NEWNS | SIGCHLD, NULL);
	if (pid < 0) {
		fprintf(stderr, "clone() failed: %m\n");
		exit(1);
	}
	close(status_pipe[1]);

	status = 1;
	ret = read(status_pipe[0], &status, sizeof(status));
	if (ret != sizeof(status) || status)
		exit(1);

	fd = open(pidfile, O_CREAT | O_EXCL | O_WRONLY, 0666);
	if (fd == -1) {
		fprintf(stderr, "Can't create a pid file %s: %m", pidfile);
		return 1;
	}
	ret = dprintf(fd, "%d", pid);
	if (ret == -1) {
		fprintf(stderr, "Can't write in a pid file\n");
		return 1;
	}
	close(fd);

	return 0;
}
