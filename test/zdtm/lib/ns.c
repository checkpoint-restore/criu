#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <inttypes.h>
#include <grp.h>
#include <string.h>
#include <errno.h>
#include <stdbool.h>
#include <sys/mount.h>
#include <sys/sysmacros.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/param.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <signal.h>
#include <sched.h>
#include <sys/socket.h>
#include <time.h>
#include <sys/prctl.h>

#include "zdtmtst.h"
#include "ns.h"

int criu_status_in = -1, criu_status_in_peer = -1, criu_status_out = -1;

extern int pivot_root(const char *new_root, const char *put_old);
static int prepare_mntns(void)
{
	int dfd, ret;
	char *root, *criu_path, *dev_path, *zdtm_bind;
	char path[PATH_MAX];
	char bind_path[PATH_MAX];

	root = getenv("ZDTM_ROOT");
	if (!root) {
		fprintf(stderr, "ZDTM_ROOT isn't set\n");
		return -1;
	}

	/*
	 * In a new userns all mounts are locked to protect what is
	 * under them. So we need to create another mount for the
	 * new root.
	 */
	if (mount(root, root, NULL, MS_SLAVE, NULL)) {
		fprintf(stderr, "Can't bind-mount root: %m\n");
		return -1;
	}

	if (mount(root, root, NULL, MS_BIND | MS_REC, NULL)) {
		fprintf(stderr, "Can't bind-mount root: %m\n");
		return -1;
	}

	zdtm_bind = getenv("ZDTM_BIND");
	if (zdtm_bind) {
		/*
		 * Bindmount the directory to itself.
		 * e.g.: The mnt_ro_root test makes "/" mount readonly, but we
		 * still want to write logs to /zdtm/static/ so let's make it
		 * separate writable bind mount.
		 */
		snprintf(bind_path, sizeof(bind_path),  "%s/%s", root, zdtm_bind);
		if (mount(bind_path, bind_path, NULL, MS_BIND, NULL)) {
			fprintf(stderr, "Can't bind-mount ZDTM_BIND: %m\n");
			return -1;
		}
	}

	dev_path = getenv("ZDTM_DEV");
	if (dev_path) {
		snprintf(path, sizeof(path), "%s/dev", root);
		if (mount(dev_path, path, NULL, MS_BIND, NULL)) {
			pr_perror("Unable to mount %s",  path);
			return -1;
		}
		if (mount(NULL, path, NULL, MS_PRIVATE, NULL)) {
			pr_perror("Unable to mount %s",  path);
			return -1;
		}
	}

	criu_path = getenv("ZDTM_CRIU");
	if (criu_path) {
		snprintf(path, sizeof(path), "%s%s", root, criu_path);
		if (mount(criu_path, path, NULL, MS_BIND, NULL) || mount(NULL, path, NULL, MS_PRIVATE, NULL)) {
			pr_perror("Unable to mount %s", path);
			return -1;
		}
	}

	/* Move current working directory to the new root */
	ret = readlink("/proc/self/cwd", path, sizeof(path) - 1);
	if (ret < 0)
		return -1;
	path[ret] = 0;

	dfd = open(path, O_RDONLY | O_DIRECTORY);
	if (dfd == -1) {
		fprintf(stderr, "open(.) failed: %m\n");
		return -1;
	}

	if (chdir(root)) {
		fprintf(stderr, "chdir(%s) failed: %m\n", root);
		return -1;
	}
	if (mkdir("old", 0777) && errno != EEXIST) {
		fprintf(stderr, "mkdir(old) failed: %m\n");
		return -1;
	}

	if (pivot_root(".", "./old")) {
		fprintf(stderr, "pivot_root(., ./old) failed: %m\n");
		return -1;
	}

	if (mount("./old", "./old", NULL, MS_SLAVE | MS_REC, NULL)) {
		fprintf(stderr, "Can't bind-mount root: %m\n");
		return -1;
	}

	/*
	 * proc and sysfs can be mounted in an unprivileged namespace,
	 * if they are already mounted when the user namespace is created.
	 * So ./old must be umounted after mounting /proc and /sys.
	 */
	if (mount("proc", "/proc", "proc", MS_MGC_VAL | MS_NOSUID | MS_NOEXEC | MS_NODEV, NULL)) {
		fprintf(stderr, "mount(/proc) failed: %m\n");
		return -1;
	}

	if (mount("zdtm_run", "/run", "tmpfs", 0, NULL)) {
		fprintf(stderr, "Unable to mount /run: %m\n");
		return -1;
	}

	if (umount2("./old", MNT_DETACH)) {
		fprintf(stderr, "umount(./old) failed: %m\n");
		return -1;
	}

	if (mount("pts", "/dev/pts", "devpts", MS_MGC_VAL, "mode=666,ptmxmode=666,newinstance")) {
		fprintf(stderr, "mount(/dev/pts) failed: %m\n");
		return -1;
	}
	/*
	 * If CONFIG_DEVPTS_MULTIPLE_INSTANCES=n, then /dev/pts/ptmx
	 * does not exist. Fall back to creating the device with
	 * mknod() in that case.
	 */
	if (access("/dev/pts/ptmx", F_OK) == 0) {
		if (symlink("pts/ptmx", "/dev/ptmx") && errno != EEXIST) {
			fprintf(stderr, "symlink(/dev/ptmx) failed: %m\n");
			return -1;
		}
	} else {
		if (mknod("/dev/ptmx", 0666 | S_IFCHR, makedev(5, 2)) == 0) {
			chmod("/dev/ptmx", 0666);
		} else if (errno != EEXIST) {
			fprintf(stderr, "mknod(/dev/ptmx) failed: %m\n");
			return -1;
		}
	}

	if (fchdir(dfd)) {
		fprintf(stderr, "fchdir() failed: %m\n");
		return -1;
	}
	close(dfd);

	return 0;
}

static int prepare_namespaces(void)
{
	if (setuid(0) || setgid(0) || setgroups(0, NULL)) {
		fprintf(stderr, "set*id failed: %m\n");
		return -1;
	}

	system("ip link set up dev lo");

	if (prepare_mntns())
		return -1;

	return 0;
}

#define NS_STACK_SIZE 4096

/* All arguments should be above stack, because it grows down */
struct ns_exec_args {
	char stack[NS_STACK_SIZE] __stack_aligned__;
	char stack_ptr[0];
	int argc;
	char **argv;
	int status_pipe[2];
};

static void ns_sig_hand(int signo)
{
	int status, len = 0;
	pid_t pid;
	char buf[128] = "";

	if (signo == SIGTERM) {
		futex_set_and_wake(&sig_received, signo);
		len = snprintf(buf, sizeof(buf), "Time to stop and check\n");
		goto write_out;
	}

	while (1) {
		pid = waitpid(-1, &status, WNOHANG);
		if (pid == 0)
			return;
		if (pid == -1) {
			if (errno == ECHILD) {
				if (futex_get(&sig_received))
					return;
				futex_set_and_wake(&sig_received, signo);
				len = snprintf(buf, sizeof(buf), "All test processes exited\n");
			} else {
				len = snprintf(buf, sizeof(buf), "wait() failed: %m\n");
			}
			goto write_out;
		}
		if (status)
			fprintf(stderr, "%d return %d\n", pid, status);
	}

	return;
write_out:
	/* fprintf can't be used in a sighandler due to glibc locks */
	write(STDERR_FILENO, buf, MIN(len, sizeof(buf)));
}

#ifndef CLONE_NEWTIME
#define CLONE_NEWTIME 0x00000080 /* New time namespace */
#endif

static inline int _settime(clockid_t clk_id, time_t offset)
{
	int fd, len;
	char buf[4096];

	if (clk_id == CLOCK_MONOTONIC_COARSE || clk_id == CLOCK_MONOTONIC_RAW)
		clk_id = CLOCK_MONOTONIC;

	len = snprintf(buf, sizeof(buf), "%d %" PRId64 " 0", clk_id, (int64_t)offset);

	fd = open("/proc/self/timens_offsets", O_WRONLY);
	if (fd < 0) {
		fprintf(stderr, "open(/proc/self/timens_offsets): %m");
		return -1;
	}

	if (write(fd, buf, len) != len) {
		fprintf(stderr, "write(/proc/self/timens_offsets): %m");
		return -1;
	}

	if (close(fd)) {
		fprintf(stderr, "close(/proc/self/timens_offsets): %m");
		return -1;
	}

	return 0;
}

#define STATUS_FD 255
static int ns_exec(void *_arg)
{
	struct ns_exec_args *args = (struct ns_exec_args *)_arg;
	char buf[4096];
	int ret;

	close(args->status_pipe[0]);

	setsid();

	prctl(PR_SET_DUMPABLE, 1, 0, 0, 0);
	ret = dup2(args->status_pipe[1], STATUS_FD);
	if (ret < 0) {
		fprintf(stderr, "dup2() failed: %m\n");
		return -1;
	}
	close(args->status_pipe[1]);
	read(STATUS_FD, buf, sizeof(buf));
	shutdown(STATUS_FD, SHUT_RD);

	if (prepare_namespaces())
		return -1;

	setenv("ZDTM_NEWNS", "2", 1);
	execvp(args->argv[0], args->argv);
	fprintf(stderr, "exec(%s) failed: %m\n", args->argv[0]);
	return -1;
}

static int create_timens(void)
{
	int fd;

	if (unshare(CLONE_NEWTIME)) {
		if (errno == EINVAL) {
			fprintf(stderr, "timens isn't supported\n");
			return 0;
		} else {
			fprintf(stderr, "unshare(CLONE_NEWTIME) failed: %m");
			exit(1);
		}
	}

	if (_settime(CLOCK_MONOTONIC, 10 * 24 * 60 * 60))
		exit(1);
	if (_settime(CLOCK_BOOTTIME, 20 * 24 * 60 * 60))
		exit(1);

	fd = open("/proc/self/ns/time_for_children", O_RDONLY);
	if (fd < 0)
		exit(1);
	if (setns(fd, 0))
		exit(1);
	close(fd);

	return 0;
}

int ns_init(int argc, char **argv)
{
	struct sigaction sa = {
		.sa_handler = ns_sig_hand,
		.sa_flags = SA_RESTART,
	};
	int ret, fd, status_pipe = STATUS_FD;
	char buf[128], *x;
	pid_t pid;
	bool reap;

	ret = fcntl(status_pipe, F_SETFD, FD_CLOEXEC);
	if (ret == -1) {
		fprintf(stderr, "fcntl failed %m\n");
		exit(1);
	}

	if (create_timens())
		exit(1);

	if (init_notify()) {
		fprintf(stderr, "Can't init pre-dump notification: %m");
		exit(1);
	}

	reap = getenv("ZDTM_NOREAP") == NULL;

	sigemptyset(&sa.sa_mask);
	sigaddset(&sa.sa_mask, SIGTERM);
	if (reap)
		sigaddset(&sa.sa_mask, SIGCHLD);

	if (sigaction(SIGTERM, &sa, NULL)) {
		fprintf(stderr, "Can't set SIGTERM handler: %m\n");
		exit(1);
	}

	x = malloc(strlen(pidfile) + 3);
	sprintf(x, "%sns", pidfile);
	pidfile = x;

	/* Start test */
	pid = fork();
	if (pid < 0) {
		fprintf(stderr, "fork() failed: %m\n");
		exit(1);
	} else if (pid == 0) {
		close(status_pipe);
		unsetenv("ZDTM_NEWNS");
		return 0; /* Continue normal test startup */
	}

	ret = -1;
	if (waitpid(pid, &ret, 0) < 0)
		fprintf(stderr, "waitpid() failed: %m\n");
	else if (ret)
		fprintf(stderr, "The test returned non-zero code %d\n", ret);

	if (reap && sigaction(SIGCHLD, &sa, NULL)) {
		fprintf(stderr, "Can't set SIGCHLD handler: %m\n");
		exit(1);
	}

	while (reap && 1) {
		int status;

		pid = waitpid(-1, &status, WNOHANG);
		if (pid == 0)
			break;
		if (pid < 0) {
			fprintf(stderr, "waitpid() failed: %m\n");
			exit(1);
		}
		if (status)
			fprintf(stderr, "%d return %d\n", pid, status);
	}

	/* Daemonize */
	write(status_pipe, &ret, sizeof(ret));
	close(status_pipe);
	if (ret)
		exit(ret);

	/* suspend/resume */
	test_waitsig();

	fd = open(pidfile, O_RDONLY);
	if (fd == -1) {
		fprintf(stderr, "open(%s) failed: %m\n", pidfile);
		exit(1);
	}
	ret = read(fd, buf, sizeof(buf) - 1);
	if (ret == -1) {
		fprintf(stderr, "read() failed: %m\n");
		exit(1);
	}
	buf[ret] = '\0';

	pid = atoi(buf);
	fprintf(stderr, "kill(%d, SIGTERM)\n", pid);
	if (pid > 0)
		kill(pid, SIGTERM);

	ret = 0;
	if (reap) {
		while (true) {
			pid_t child;
			ret = -1;

			child = waitpid(-1, &ret, 0);
			if (child < 0) {
				fprintf(stderr, "Unable to wait a test process: %m");
				exit(1);
			}
			if (child == pid) {
				fprintf(stderr, "The test returned 0x%x", ret);
				exit(!(ret == 0));
			}
			if (ret)
				fprintf(stderr, "The %d process exited with 0x%x", child, ret);
		}
	} else {
		waitpid(pid, NULL, 0);
	}

	exit(1);
}

#define UID_MAP "0 20000 20000\n100000 200000 50000"
#define GID_MAP "0 400000 50000\n50000 500000 100000"
void ns_create(int argc, char **argv)
{
	pid_t pid;
	int ret, status;
	struct ns_exec_args args;
	int flags;
	char *pidf;

	args.argc = argc;
	args.argv = argv;

	ret = socketpair(AF_UNIX, SOCK_SEQPACKET, 0, args.status_pipe);
	if (ret) {
		fprintf(stderr, "Pipe() failed %m\n");
		exit(1);
	}

	flags = CLONE_NEWPID | CLONE_NEWNS | CLONE_NEWUTS | CLONE_NEWNET | CLONE_NEWIPC | SIGCHLD;

	if (getenv("ZDTM_USERNS"))
		flags |= CLONE_NEWUSER;

	pid = clone(ns_exec, args.stack_ptr, flags, &args);
	if (pid < 0) {
		fprintf(stderr, "clone() failed: %m\n");
		exit(1);
	}

	close(args.status_pipe[1]);

	if (flags & CLONE_NEWUSER) {
		char pname[PATH_MAX];
		int fd;

		snprintf(pname, sizeof(pname), "/proc/%d/uid_map", pid);
		fd = open(pname, O_WRONLY);
		if (fd < 0) {
			fprintf(stderr, "open(%s): %m\n", pname);
			exit(1);
		}
		if (write(fd, UID_MAP, sizeof(UID_MAP)) < 0) {
			fprintf(stderr, "write(" UID_MAP "): %m\n");
			exit(1);
		}
		close(fd);

		snprintf(pname, sizeof(pname), "/proc/%d/gid_map", pid);
		fd = open(pname, O_WRONLY);
		if (fd < 0) {
			fprintf(stderr, "open(%s): %m\n", pname);
			exit(1);
		}
		if (write(fd, GID_MAP, sizeof(GID_MAP)) < 0) {
			fprintf(stderr, "write(" GID_MAP "): %m\n");
			exit(1);
		}
		close(fd);
	}
	shutdown(args.status_pipe[0], SHUT_WR);

	pidf = pidfile;
	pidfile = malloc(strlen(pidfile) + 13);
	sprintf(pidfile, "%s%s", pidf, INPROGRESS);
	if (write_pidfile(pid)) {
		fprintf(stderr, "Preparations fail\n");
		exit(1);
	}

	status = 1;
	ret = read(args.status_pipe[0], &status, sizeof(status));
	if (ret != sizeof(status) || status) {
		fprintf(stderr, "The test failed (%d, %d)\n", ret, status);
		exit(1);
	}
	ret = read(args.status_pipe[0], &status, sizeof(status));
	if (ret != 0) {
		fprintf(stderr, "Unexpected message from test\n");
		exit(1);
	}

	unlink(pidfile);
	pidfile = pidf;

	if (write_pidfile(pid))
		exit(1);

	exit(0);
}
