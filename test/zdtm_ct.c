#include <sched.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/mount.h>
#include <unistd.h>
#include <time.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/utsname.h>

#ifndef CLONE_NEWTIME
#define CLONE_NEWTIME 0x00000080 /* New time namespace */
#endif

static inline int _settime(clockid_t clk_id, time_t offset)
{
	int fd, len;
	char buf[4096];

	if (clk_id == CLOCK_MONOTONIC_COARSE || clk_id == CLOCK_MONOTONIC_RAW)
		clk_id = CLOCK_MONOTONIC;

	len = snprintf(buf, sizeof(buf), "%d %ld 0", clk_id, offset);

	fd = open("/proc/self/timens_offsets", O_WRONLY);
	if (fd < 0) {
		fprintf(stderr, "/proc/self/timens_offsets: %m");
		return -1;
	}

	if (write(fd, buf, len) != len) {
		fprintf(stderr, "/proc/self/timens_offsets: %m");
		return -1;
	}

	close(fd);

	return 0;
}

static int create_timens()
{
	struct utsname buf;
	unsigned major, minor;
	int fd, ret;

	/*
	 * Before the 5.11 kernel, there is a known issue.
	 * start_time in /proc/pid/stat is printed in the host time
	 * namespace, but /proc/uptime is shown in the current time
	 * namespace, so criu can't compare them to detect tasks that
	 * reuse old pids.
	 */
	ret = uname(&buf);
	if (ret)
		return -1;

	if (sscanf(buf.release, "%u.%u", &major, &minor) != 2)
		return -1;

	if ((major <= 5) || (major == 5 && minor < 11)) {
		fprintf(stderr, "timens isn't supported on %s\n", buf.release);
		return 0;
	}

	if (unshare(CLONE_NEWTIME)) {
		if (errno == EINVAL) {
			fprintf(stderr, "timens isn't supported\n");
			return 0;
		} else {
			fprintf(stderr, "unshare(CLONE_NEWTIME) failed: %m");
			exit(1);
		}
	}

	if (_settime(CLOCK_MONOTONIC, 110 * 24 * 60 * 60))
		exit(1);
	if (_settime(CLOCK_BOOTTIME, 40 * 24 * 60 * 60))
		exit(1);

	fd = open("/proc/self/ns/time_for_children", O_RDONLY);
	if (fd < 0)
		exit(1);
	if (setns(fd, 0))
		exit(1);
	close(fd);

	return 0;
}

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
		if (create_timens())
			exit(1);
		if (mount(NULL, "/", NULL, MS_REC | MS_SLAVE, NULL)) {
			fprintf(stderr, "mount(/, S_REC | MS_SLAVE)): %m");
			return 1;
		}
		umount2("/proc", MNT_DETACH);
		umount2("/dev/pts", MNT_DETACH);
		if (mount("zdtm_proc", "/proc", "proc", 0, NULL)) {
			fprintf(stderr, "mount(/proc): %m");
			return 1;
		}
		if (mount("zdtm_devpts", "/dev/pts", "devpts", 0, "newinstance,ptmxmode=0666")) {
			fprintf(stderr, "mount(pts): %m");
			return 1;
		}
		if (mount("zdtm_binfmt", "/proc/sys/fs/binfmt_misc", "binfmt_misc", 0, NULL)) {
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
