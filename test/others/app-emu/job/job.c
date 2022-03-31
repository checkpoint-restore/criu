#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>

#include <fcntl.h>
#include <string.h>
#include <termios.h>

#include <signal.h>

#include <dirent.h>

static int stop = 0;

void sighandler(int sig)
{
	stop = 1;
}

int main(int argc, char *argv[])
{
	int pid, gid, sid;
	int tty_sid, tty_gid;
	int fd = fileno(stdout);
	char buf[32];
	struct dirent *de;
	DIR *fd_dir;
	sigset_t bmask, cmask;

	if (signal(SIGTERM, sighandler)) {
		printf("Unable to set a signal handler: %m\n");
		return 1;
	}

	if (!isatty(fd)) {
		printf("stdout is not tty\n");
		return -1;
	}

	pid = getpid();
	gid = getgid();
	sid = getsid(pid);

	printf("pid %d gid %d sid %d\n", pid, gid, sid);

	snprintf(buf, sizeof(buf), "/proc/%d/fd", pid);
	fd_dir = opendir(buf);
	if (!fd_dir) {
		printf("can't open %s\n", buf);
		return -1;
	}

	while ((de = readdir(fd_dir))) {
		int _fd;
		if (!strcmp(de->d_name, "."))
			continue;
		if (!strcmp(de->d_name, ".."))
			continue;

		_fd = atoi(de->d_name);
		if (_fd > 2 && _fd != fd && isatty(_fd)) {
			close(_fd);
			printf("Closed %d\n", _fd);
		}
	}
	closedir(fd_dir);

	if (ioctl(fd, TIOCGSID, &tty_sid) < 0) {
		printf("can't obtain sid on stdout\n");
		return -1;
	}
	printf("stdout sid = %d\n", tty_sid);

	if (ioctl(fd, TIOCGPGRP, &tty_gid) < 0) {
		printf("can't obtain gid on stdout\n");
		return -1;
	}
	printf("stdout gid = %d\n", tty_gid);

	sigemptyset(&cmask);
	sigemptyset(&bmask);
	sigaddset(&bmask, SIGTERM);

	sigprocmask(SIG_SETMASK, &bmask, NULL);

	printf("READY\n");

	while (!stop)
		sigsuspend(&cmask);

	if (getsid(pid) == sid)
		printf("ALIVE\n");

	return 0;
}
