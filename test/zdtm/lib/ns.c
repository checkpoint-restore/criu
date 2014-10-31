#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <grp.h>
#include <string.h>
#include <errno.h>
#include <sys/mount.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/param.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <signal.h>
#include <sched.h>
#include <sys/socket.h>

#include "ns.h"

extern int pivot_root(const char *new_root, const char *put_old);
static int prepare_mntns()
{
	int dfd, ret;
	char *root;
	char path[PATH_MAX];

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
		if (mount("/", "/", NULL, MS_PRIVATE | MS_REC, NULL)) {
			fprintf(stderr, "Can't bind-mount root: %m\n");
			return -1;
		}

		if (mount(root, root, NULL, MS_BIND | MS_REC, NULL)) {
			fprintf(stderr, "Can't bind-mount root: %m\n");
			return -1;
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

		if (mkdir("proc", 0777) && errno != EEXIST) {
			fprintf(stderr, "mkdir(proc) failed: %m\n");
			return -1;
		}

		/*
		 * proc and sysfs can be mounted in an unprivileged namespace,
		 * if they are already mounted when the user namespace is created.
		 * So ./old must be umounted after mounting /proc and /sys.
		 */
		if (mount("proc", "/proc", "proc", MS_MGC_VAL, NULL)) {
			fprintf(stderr, "mount(/proc) failed: %m\n");
			return -1;
		}

		if (umount2("./old", MNT_DETACH)) {
			fprintf(stderr, "umount(./old) failed: %m\n");
			return -1;
		}

		if (mkdir("/dev", 0755) && errno != EEXIST) {
			fprintf(stderr, "mkdir(/dev) failed: %m\n");
			return -1;
		}
		if (mkdir("/dev/pts", 0755) && errno != EEXIST) {
			fprintf(stderr, "mkdir(/dev/pts) failed: %m\n");
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

#define NS_STACK_SIZE	4096

/* All arguments should be above stack, because it grows down */
struct ns_exec_args {
	char stack[NS_STACK_SIZE];
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
	write(STDERR_FILENO, buf, MIN(len, sizeof(buf)));
}

#define STATUS_FD 255
int ns_exec(void *_arg)
{
	struct ns_exec_args *args = (struct ns_exec_args *) _arg;
	char buf[4096];
	int ret;

	close(args->status_pipe[0]);

	setsid();

	system("ip link set up dev lo");

	ret = dup2(args->status_pipe[1], STATUS_FD);
	if (ret < 0) {
		fprintf(stderr, "dup2() failed: %m\n");
		return -1;
	}
	close(args->status_pipe[1]);
	read(STATUS_FD, buf, sizeof(buf));
	shutdown(STATUS_FD, SHUT_RD);
	if (setuid(0) || setgid(0) || setgroups(0, NULL)) {
		fprintf(stderr, "set*id failed: %m\n");
		return -1;
	}

	if (prepare_mntns())
		return -1;

	setenv("ZDTM_NEWNS", "2", 1);
	execvp(args->argv[0], args->argv);
	fprintf(stderr, "exec(%s) failed: %m\n", args->argv[0]);
	return -1;
}

int ns_init(int argc, char **argv)
{
	struct sigaction sa = {
		.sa_handler	= ns_sig_hand,
		.sa_flags	= SA_RESTART,
	};
	int ret, fd, status_pipe = STATUS_FD;
	char buf[128];
	pid_t pid;

	ret = fcntl(status_pipe, F_SETFD, FD_CLOEXEC);
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

	/* Start test */
	pid = fork();
	if (pid < 0) {
		fprintf(stderr, "fork() failed: %m\n");
		exit(1);
	} else if (pid == 0) {
		setenv("ZDTM_NEWNS", "3", 1);
		ret = execvp(argv[0], argv);
		fprintf(stderr, "exec(%s) failed: %m\n", argv[0]);
		return ret;
	}

	ret = -1;
	if (waitpid(pid, &ret, 0) < 0)
		fprintf(stderr, "waitpid() failed: %m\n");
	else if (ret)
		fprintf(stderr, "The test returned non-zero code %d\n", ret);

	pid = fork();
	if (pid == 0) {
		execl("/bin/ps", "ps", "axf", "-o", "pid,sid,comm", NULL);
		fprintf(stderr, "Unable to execute ps: %m\n");
		exit(1);
	} else if (pid > 0)
		waitpid(pid, NULL, 0);

	if (sigaction(SIGCHLD, &sa, NULL)) {
		fprintf(stderr, "Can't set SIGCHLD handler: %m\n");
		exit(1);
	}

	while (1) {
		int status;

		pid = waitpid(-1, &status, WNOHANG);
		if (pid == 0)
			break;
		if (pid < 0) {
			fprintf(stderr, "waitpid() failed: %m\n");
			exit (1);
		}
		if (status)
			fprintf(stderr, "%d return %d\n", pid, status);
	}

	/* Daemonize */
	write(status_pipe, &ret, sizeof(ret));
	close(status_pipe);
	if (ret)
		return ret;

	/* suspend/resume */
	test_waitsig();

	pid = fork();
	if (pid == 0) {
		execl("/bin/ps", "ps", "axf", "-o", "pid,sid,comm", NULL);
		fprintf(stderr, "Unable to execute ps: %m\n");
		exit(1);
	} else if (pid > 0)
		waitpid(pid, NULL, 0);

	fd = open(pidfile, O_RDONLY);
	if (fd == -1) {
		fprintf(stderr, "open(%s) failed: %m\n", pidfile);
		exit(1);
	}
	ret = read(fd, buf, sizeof(buf) - 1);
	buf[ret] = '\0';
	if (ret == -1) {
		fprintf(stderr, "read() failed: %m\n");
		exit(1);
	}

	pid = atoi(buf);
	fprintf(stderr, "kill(%d, SIGTERM)\n", pid);
	if (pid > 0)
		kill(pid, SIGTERM);

	ret = 0;
	while (ret != -1)
		ret = wait(NULL);

	exit(1);
}

static int construct_root()
{
	char *root;
	int dfd;

	root = getenv("ZDTM_ROOT");
	if (!root) {
		fprintf(stderr, "ZDTM_ROOT isn't set\n");
		return -1;
	}

	dfd = open(".", O_RDONLY);
	if (dfd == -1) {
		fprintf(stderr, "open(.) failed: %m\n");
		return -1;
	}
	if (chdir(root)) {
		fprintf(stderr, "chdir(%s): %m\n", root);
		return -1;
	}

	mkdir("dev", 0777);
	chmod("dev", 0777);
	mknod("dev/null", 0777 | S_IFCHR, makedev(1, 3));
	chmod("dev/null", 0777);
	mkdir("dev/net", 0777);
	mknod("dev/net/tun", 0777 | S_IFCHR, makedev(10, 200));
	chmod("dev/net/tun", 0777);
	mknod("dev/rtc", 0777 | S_IFCHR, makedev(254, 0));
	chmod("dev/rtc", 0777);

	if (fchdir(dfd)) {
		fprintf(stderr, "fchdir() failed: %m\n");
		return -1;
	}
	close(dfd);

	return 0;
}

#define UID_MAP "0 100000 100000\n100000 200000 50000"
#define GID_MAP "0 400000 50000\n50000 500000 100000"
void ns_create(int argc, char **argv)
{
	pid_t pid;
	char pname[PATH_MAX];
	int ret, status;
	struct ns_exec_args args;
	int fd, flags;
	char *val;

	args.argc = argc;
	args.argv = argv;

	ret = socketpair(AF_UNIX, SOCK_SEQPACKET, 0, args.status_pipe);
	if (ret) {
		fprintf(stderr, "Pipe() failed %m\n");
		exit(1);
	}

	val = getenv("ZDTM_USERNS");
	if (val)
		/*
		 * CLONE_NEWIPC and CLONE_NEWUTS are excluded, because
		 * their sysctl-s are protected by CAP_SYS_ADMIN
		 */
		flags = CLONE_NEWPID | CLONE_NEWNS  |
			CLONE_NEWNET | CLONE_NEWUSER | SIGCHLD;
	else
		flags = CLONE_NEWPID | CLONE_NEWNS | CLONE_NEWUTS |
			CLONE_NEWNET | CLONE_NEWIPC | SIGCHLD;

	if (construct_root())
		exit(1);

	pid = clone(ns_exec, args.stack_ptr, flags, &args);
	if (pid < 0) {
		fprintf(stderr, "clone() failed: %m\n");
		exit(1);
	}

	close(args.status_pipe[1]);

	if (val) {
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

	pidfile = getenv("ZDTM_PIDFILE");
	if (pidfile == NULL) {
		fprintf(stderr, "ZDTM_PIDFILE isn't defined");
		exit(1);
	}
	fd = open(pidfile, O_CREAT | O_EXCL | O_WRONLY, 0666);
	if (fd == -1) {
		fprintf(stderr, "Can't create the file %s: %m\n", pidfile);
		exit(1);
	}
	if (dprintf(fd, "%d", pid) == -1) {
		fprintf(stderr, "Can't write in the file %s: %m\n", pidfile);
		exit(1);
	}
	close(fd);

	exit(0);
}

