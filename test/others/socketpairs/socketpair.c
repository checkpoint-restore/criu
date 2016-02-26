/*
 * A simple demo/test program using criu's --inherit-fd command line
 * option to restore a process with an external unix socket.
 * Extending inherit's logic to unix sockets created by socketpair(..) syscall.
*/

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <sys/socket.h>

typedef void (*sighandler_t)(int);
typedef unsigned long ulong;

/* colors */
#define CS_PARENT 		"\033[00;32m"
#define CS_CHILD 		"\033[00;33m"
#define CS_DUMP 		"\033[00;34m"
#define CS_RESTORE 		"\033[00;35m"
#define CE			"\033[0m"

#define die(fmt, ...) do { \
	fprintf(stderr, fmt ": %m\n", __VA_ARGS__); \
	if (getpid() == parent_pid) { \
		(void)kill(0, 9); \
		exit(1); \
	} \
	_exit(1); \
} while (0)

#define READ_FD		0	/* pipe read fd */
#define WRITE_FD	1	/* pipe write fd */
#define CLASH_FD	3	/* force inherit fd clash */

#define MAX_FORKS	3	/* child, checkpoint, restore */

#define CRIU_BINARY		"../../../criu/criu"
#define IMG_DIR			"images"
#define DUMP_LOG_FILE		"dump.log"
#define RESTORE_LOG_FILE	"restore.log"
#define RESTORE_PID_FILE	"restore.pid"
#define INHERIT_FD_OPTION	"--inherit-fd"
#define OLD_LOG_FILE		"/tmp/oldlog"
#define NEW_LOG_FILE		"/tmp/newlog"

/*
 * Command line options (see usage()).
 */

char *cli_flags = "hm:nv";
int max_msgs = 10;
int vflag;
int nflag;

char pid_number[8];
char inh_unixsk_opt[16];
char inh_unixsk_arg[64];
char external_sk_ino[32];

char *dump_argv[] = {
	"criu", "dump",
	"-D", IMG_DIR, "-o", DUMP_LOG_FILE,
	"-v4",
	external_sk_ino,
	"-t", pid_number,
	NULL
};

char *restore_argv[] = {
	"criu", "restore", "-d",
	"-D", IMG_DIR, "-o", RESTORE_LOG_FILE,
	"--pidfile", RESTORE_PID_FILE,
	"-v4", "-x",
	inh_unixsk_opt, inh_unixsk_arg,
	NULL
};

int max_forks;
int parent_pid;
int child_pid;
int criu_dump_pid;
int criu_restore_pid;

/* prototypes */
void chld_handler(int signum);
int parent(int *socketfd, const char *ino_child_sk);
int child(int *socketfd, int dupfd, int newfd);
void checkpoint_child(int child_pid, int *old_socket_namefd);
void restore_child(int *new_socketfd, const char *old_socket_name);
void write_to_fd(int fd, char *name, int i, int newline);
void ls_proc_fd(int fd);
char *socket_name(int fd);
ino_t socket_inode(int fd);
char *who(pid_t pid);
void socketpair_safe(int socketfd[2]);
pid_t fork_safe(void);
void signal_safe(int signum, sighandler_t handler);
int open_safe(char *pathname, int flags);
void close_safe(int fd);
void write_safe(int fd, char *buf, int count);
int read_safe(int fd, char *buf, int count);
int dup_safe(int oldfd);
void move_fd(int oldfd, int newfd);
void mkdir_safe(char *dirname, int mode);
void unlink_safe(char *pathname);
void execv_safe(char *path, char *argv[], int ls);
pid_t waitpid_safe(pid_t pid, int *status, int options, int id);
void prctl_safe(int option, ulong arg2, ulong arg3, ulong arg4, ulong arg5);
int dup2_safe(int oldfd, int newfd);

void usage(char *cmd)
{
	printf("Usage: %s [%s]\n", cmd, cli_flags);
	printf("-h\tprint this help and exit\n");
	printf("-m\tcount of send messages (by default 10 will send from child) \n");
	printf("-n\tdo not use the %s option\n", INHERIT_FD_OPTION);
	printf("-v\tverbose mode (list contents of /proc/<pid>/fd)\n");
}

int main(int argc, char *argv[])
{
	int ret;
	int opt;
	int socketfd[2];

	while ((opt = getopt(argc, argv, cli_flags)) != -1) {
		switch (opt) {
		case 'h':
			usage(argv[0]);
			return 0;
		case 'm':
			max_msgs = atoi(optarg);
			break;
		case 'n':
			nflag++;
			break;
		case 'v':
			vflag++;
			break;
		case '?':
			if ('m' == optopt)
				fprintf (stderr, "Option -%c requires an argument.\n", optopt);
			else
			fprintf (
				stderr,
				"Unknown option character `\\x%x'.\n",
				optopt);
			return 1;
		default:
			usage(argv[0]);
			return 1;
		}
	}

	setbuf(stdout, NULL);
	setbuf(stderr, NULL);
	mkdir_safe(IMG_DIR, 0700);

	socketpair_safe(socketfd);
	child_pid = fork_safe();
	if (child_pid > 0) {
		parent_pid = getpid();

		signal_safe(SIGCHLD, chld_handler);
		prctl_safe(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0);

		snprintf(external_sk_ino, sizeof(external_sk_ino), "--ext-unix-sk=%u",
			(unsigned int)socket_inode(socketfd[WRITE_FD]));

		char unix_sk_ino[32] = {0};
		strcpy(unix_sk_ino, socket_name(socketfd[WRITE_FD]));
		close_safe(socketfd[WRITE_FD]);
		ret = parent(socketfd, unix_sk_ino);
	} else {
		/* child */
		int dupfd = -1;
		int openfd = -1;
		int logfd;

		child_pid = getpid();

		close_safe(socketfd[READ_FD]);
		setsid();
		logfd = open_safe(OLD_LOG_FILE, O_WRONLY | O_APPEND | O_CREAT);
		dup2_safe(logfd, 1);
		dup2_safe(logfd, 2);
		close(logfd);
		close(0);

		ret = child(socketfd, dupfd, openfd);
	}

	return ret;
}

/*
 * Parent reads message from its pipe with the child.
 * After a couple of messages, it checkpoints the child
 * which causes the child to exit.  Parent then creates
 * a new pipe and restores the child.
 */
int parent(int *socketfd, const char *ino_child_sk)
{
	char buf[32];
	int nread;

	nread = 0;
	while (max_forks <= MAX_FORKS) {
		if (read_safe(socketfd[READ_FD], buf, sizeof buf) == 0)
			continue;
		nread++;
		if (vflag && nread == 1)
			ls_proc_fd(-1);

		printf(
			"%s read %s from %s\n",
			who(0), buf,
			socket_name(socketfd[READ_FD]));


		if (nread == (max_msgs / 2)) {
			checkpoint_child(child_pid, socketfd);

			if (!nflag) {
				close_safe(socketfd[READ_FD]);

				/* create a new one */
				printf("%s creating a new socket\n", who(0));
				socketpair_safe(socketfd);
			}

			restore_child(socketfd, ino_child_sk);
		}
	}

	return 0;
}

/*
 * Child sends a total of max_messages messages to its
 * parent, half before checkpoint and half after restore.
 */
int child(int *socketfd, int dupfd, int openfd)
{
	int i;
	int fd;
	int num_wfds;
	struct timespec req = { 1, 0 };

	/*
	 * Count the number of pipe descriptors we'll be
	 * writing to.  At least 1 (for socketfd[WRITE_FD])
	 * and at most 3.
	 */
	num_wfds = 1;
	if (dupfd >= 0)
		num_wfds++;
	if (openfd >= 0)
		num_wfds++;

	for (i = 0; i < max_msgs; i++) {
		/* print first time and after checkpoint */
		if (vflag && (i == 0 || i == (max_msgs / 2)))
			ls_proc_fd(-1);

		switch (i % num_wfds) {
			case 0: fd = socketfd[WRITE_FD]; break;
			case 1: fd = openfd; break;
			case 2: fd = openfd; break;
		}

		write_to_fd(fd, socket_name(socketfd[WRITE_FD]), i+1, 0);
		/*
		 * Since sleep will be interrupted by C/R, make sure
		 * to sleep an entire second to minimize the chance of
		 * writing before criu restore has exited.  If criu is
		 * still around and we write to a broken pipe, we'll be
		 * killed but SIGCHLD will be delivered to criu instead
		 * of parent.
		 */
		while (nanosleep(&req, NULL))
			;
		printf("\n");
	}

	return 0;
}

void chld_handler(int signum)
{
	int status;
	pid_t pid;

	pid = waitpid_safe(-1, &status, WNOHANG, 1);
	if (WIFEXITED(status))
		status = WEXITSTATUS(status);
	if (pid == child_pid) {
		printf("%s %s exited with status %d\n", who(0),
			who(pid), status);
		/* if child exited successfully, we're done */
		if (status == 0)
			exit(0);
		/* checkpoint kills the child */
		if (status != 9)
			exit(status);
	}
}

void checkpoint_child(int child_pid, int *socketfd)
{
	/* prepare -t <pid> */
	snprintf(pid_number, sizeof pid_number, "%d", child_pid);

	criu_dump_pid = fork_safe();
	if (criu_dump_pid > 0) {
		int status;
		pid_t pid;

		pid = waitpid_safe(criu_dump_pid, &status, 0, 2);
		if (WIFEXITED(status))
			status = WEXITSTATUS(status);
		printf("%s %s exited with status %d\n", who(0),
			who(pid), status);
		if (status)
			exit(status);
	} else {
		close(socketfd[READ_FD]);
		criu_dump_pid = getpid();
		execv_safe(CRIU_BINARY, dump_argv, 0);
	}
}

void restore_child(int *new_socketfd, const char *old_sock_name)
{
	char buf[64];

	criu_restore_pid = fork_safe();
	if (criu_restore_pid > 0) {
		int status;
		pid_t pid;

		if (!nflag)
			close_safe(new_socketfd[WRITE_FD]);

		pid = waitpid_safe(criu_restore_pid, &status, 0, 3);
		if (WIFEXITED(status))
			status = WEXITSTATUS(status);

		printf("%s %s exited with status %d\n", who(0),
			who(pid), status);

		if (status)
			exit(status);
	} else {
		criu_restore_pid = getpid();

		if (!nflag) {
			close_safe(new_socketfd[READ_FD]);
			move_fd(new_socketfd[WRITE_FD], CLASH_FD);

			/* --inherit-fd fd[CLASH_FD]:socket[xxxxxx] */
			snprintf(inh_unixsk_opt, sizeof inh_unixsk_opt,
				"%s", INHERIT_FD_OPTION);
			snprintf(inh_unixsk_arg, sizeof inh_unixsk_arg, "fd[%d]:%s",
				CLASH_FD, old_sock_name);

			restore_argv[11] = inh_unixsk_opt;
			restore_argv[13] = NULL;
		} else
			restore_argv[11] = NULL;

		snprintf(buf, sizeof buf, "%s/%s", IMG_DIR, RESTORE_PID_FILE);
		unlink_safe(buf);
		execv_safe(CRIU_BINARY, restore_argv, 1);
	}
}

void write_to_fd(int fd, char *name, int i, int newline)
{
	int n;
	char buf[16];	/* fit "hello d\n" for small d */

	n = snprintf(buf, sizeof buf, "hello %d", i);

	printf("%s writing %s to %s via fd %d\n", who(0), buf, name, fd);

	if (newline) {
		buf[n++] = '\n';
		buf[n] = '\0';
	}
	write_safe(fd, buf, strlen(buf));
}

void ls_proc_fd(int fd)
{
	char cmd[128];

	if (fd == -1)
		snprintf(cmd, sizeof cmd, "ls -l /proc/%d/fd", getpid());
	else
		snprintf(cmd, sizeof cmd, "ls -l /proc/%d/fd/%d", getpid(), fd);
	printf("%s %s\n", who(0), cmd);
	system(cmd);
}

char *socket_name(int fd)
{
	static char sock_name[64];
	char path[64];

	snprintf(path, sizeof path, "/proc/self/fd/%d", fd);
	if (readlink(path, sock_name, sizeof sock_name) == -1)
		die("readlink: path=%s", path);
	return sock_name;
}

ino_t socket_inode(int fd)
{
         struct stat sbuf;

         if (fstat(fd, &sbuf) == -1)
                 die("fstat: fd=%i", fd);

         return sbuf.st_ino;
}

/*
 * Use two buffers to support two calls to
 * this function in a printf argument list.
 */
char *who(pid_t pid)
{
	static char pidstr1[64];
	static char pidstr2[64];
	static char *cp;
	char *np;
	char *ep;
	int p;

	p = pid ? pid : getpid();
	if (p == parent_pid) {
		np = "parent";
		ep = CS_PARENT;
	} else if (p == child_pid) {
		np = "child";
		ep = CS_CHILD;
	} else if (p == criu_dump_pid) {
		np = "dump";
		ep = CS_DUMP;
	} else if (p == criu_restore_pid) {
		np = "restore";
		ep = CS_RESTORE;
	} else
		np = "???";

	cp = (cp == pidstr1) ? pidstr2 : pidstr1;
	snprintf(cp, sizeof pidstr1, "%s[%s %d]", pid ? "" : ep, np, p);
	return cp;
}

void socketpair_safe(int socketfd[2])
{
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, socketfd) == -1)
		die("socketpair %p", socketfd);
}

pid_t fork_safe(void)
{
	pid_t pid;

	if ((pid = fork()) == -1)
		die("fork: pid=%d", pid);
	max_forks++;
	return pid;
}

void signal_safe(int signum, sighandler_t handler)
{
	if (signal(signum, handler) == SIG_ERR)
		die("signal: signum=%d", signum);
}

int open_safe(char *pathname, int flags)
{
	int fd;

	if ((fd = open(pathname, flags, 0777)) == -1)
		die("open: pathname=%s", pathname);
	return fd;
}

void close_safe(int fd)
{
	if (close(fd) == -1)
		die("close: fd=%d", fd);
}

void write_safe(int fd, char *buf, int count)
{
	if (write(fd, buf, count) != count) {
		die("write: fd=%d buf=\"%s\" count=%d errno=%d",
			fd, buf, count, errno);
	}
}

int read_safe(int fd, char *buf, int count)
{
	int n;

	if ((n = read(fd, buf, count)) < 0)
		die("read: fd=%d count=%d", fd, count);
	buf[n] = '\0';
	return n;
}

int dup_safe(int oldfd)
{
	int newfd;

	if ((newfd = dup(oldfd)) == -1)
		die("dup: oldfd=%d", oldfd);
	return newfd;
}

int dup2_safe(int oldfd, int newfd)
{
	if (dup2(oldfd, newfd) != newfd)
		die("dup2: oldfd=%d newfd=%d", oldfd, newfd);
	return newfd;
}

void move_fd(int oldfd, int newfd)
{
	if (oldfd != newfd) {
		dup2_safe(oldfd, newfd);
		close_safe(oldfd);
	}
}

void mkdir_safe(char *dirname, int mode)
{
	if (mkdir(dirname, mode) == -1 && errno != EEXIST)
		die("mkdir dirname=%s mode=0x%x\n", dirname, mode);
}

void unlink_safe(char *pathname)
{
	if (unlink(pathname) == -1 && errno != ENOENT) {
		die("unlink: pathname=%s\n", pathname);
	}
}

void execv_safe(char *path, char *argv[], int ls)
{
	int i;
	struct timespec req = { 0, 1000000 };

	printf("\n%s ", who(0));
	for (i = 0; argv[i] != NULL; i++)
		printf("%s ", argv[i]);
	printf("\n");

	/* give parent a chance to wait for us */
	while (nanosleep(&req, NULL))
		;

	if (vflag && ls)
		ls_proc_fd(-1);

	execv(path, argv);
	die("execv: path=%s", path);
}

pid_t waitpid_safe(pid_t pid, int *status, int options, int id)
{
	pid_t p;

	p = waitpid(pid, status, options);
	if (p == -1)
		fprintf(stderr, "waitpid pid=%d id=%d %m\n", pid, id);
	return p;
}

void prctl_safe(int option, ulong arg2, ulong arg3, ulong arg4, ulong arg5)
{
	if (prctl(option, arg2, arg3, arg4, arg5) == -1)
		die("prctl: option=0x%x", option);
}
