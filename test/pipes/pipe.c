/*
 * A simple demo/test program using criu's --inherit-fd command line
 * option to restore a process with (1) an external pipe and (2) a
 * new log file.
 *
 * Note that it's possible to restore the process without --inherit-fd,
 * but when it reads from or writes to the pipe, it will get a broken
 * pipe signal.
 *
 * Also note that changing the log file during restore has nothing to do
 * with the pipe.  It's just a nice feature for cases where it's desirable
 * to have a restored process use a different file then the original one.
 * 
 * The parent process spawns a child that will write messages to its
 * parent through a pipe.  After a couple of messages, parent invokes
 * criu to checkpoint the child.  Since the child exits after checkpoint,
 * its pipe will be broken.  Parent sets up a new pipe and invokes criu
 * to restore the child using the new pipe (instead of the old one).
 * The restored child exits after writing a couple more messages.
 *
 * To make sure that fd clashes are correctly handled during restore,
 * child can optionally open a regular file and move it to a clashing fd.
 *
 * Make sure CRIU_BINARY defined below points to the right criu.
 *
 *	$ cc -Wall -o pipe pipe.c
 *	$ sudo ./pipe -v
 *
 *      The following should all succeed:
 *
 *	$ sudo ./pipe -q && echo OK
 *	$ sudo ./pipe -qc && echo OK
 *	$ sudo ./pipe -qcl && echo OK
 *	$ sudo ./pipe -qd && echo OK
 *	$ sudo ./pipe -qdc && echo OK
 *	$ sudo ./pipe -qdcl && echo OK
 *
 *      The following should all fail:
 *
 *	$ sudo ./pipe -qn || echo $?
 *	$ sudo ./pipe -qo || echo $?
 *	$ sudo ./pipe -qr || echo $?
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

typedef void (*sighandler_t)(int);
typedef unsigned long ulong;

/* colors */
#define CS_PARENT 		"\033[00;32m"
#define CS_CHILD 		"\033[00;33m"
#define CS_DUMP 		"\033[00;34m"
#define CS_RESTORE 		"\033[00;35m"
#define CE			"\033[0m"

#define die(fmt, ...) do { \
	if (!qflag) \
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

#define CRIU_BINARY		"../../criu"
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
char *cli_flags = "cdhlnoqrv";

int cflag;
int dflag;
int lflag;
int nflag;
int oflag;
int qflag;
int rflag;
int vflag;

char pid_number[8];
char inh_pipe_opt[16];
char inh_pipe_arg[64];
char inh_file_opt[16];
char inh_file_arg[64];

char *dump_argv[] = {
	"criu", "dump",
	"-D", IMG_DIR, "-o", DUMP_LOG_FILE,
	"-v4",
	"-t", pid_number,
	NULL
};

char *restore_argv[] = {
	"criu", "restore", "-d",
	"-D", IMG_DIR, "-o", RESTORE_LOG_FILE,
	"--pidfile", RESTORE_PID_FILE,
	"-v4",
	inh_pipe_opt, inh_pipe_arg,
	inh_file_opt, inh_file_arg,
	NULL
};

int max_msgs;
int max_forks;
int parent_pid;
int child_pid;
int criu_dump_pid;
int criu_restore_pid;

/* prototypes */
void chld_handler(int signum);
int parent(int *pipefd);
int child(int *pipefd, int dupfd, int newfd);
void checkpoint_child(int child_pid, int *pipefd);
void restore_child(int *new_pipefd, char *old_pipe_name);
void write_to_fd(int fd, char *name, int i, int newline);
void ls_proc_fd(int fd);
char *pipe_name(int fd);
char *who(pid_t pid);
void pipe_safe(int pipefd[2]);
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
	printf("-c\tcause a clash during restore by opening %s as fd %d\n",
		OLD_LOG_FILE, CLASH_FD);
	printf("-d\tdup the pipe and write to it\n");
	printf("-l\tchange log file from %s to %s during restore\n",
		OLD_LOG_FILE, NEW_LOG_FILE);

	printf("\n");
	printf("The following flags should cause restore failure\n");
	printf("-n\tdo not use the %s option\n", INHERIT_FD_OPTION);
	printf("-o\topen the pipe via /proc/<pid>/fd and write to it\n");
	printf("-r\tspecify read end of pipe during restore\n");

	printf("\n");
	printf("Miscellaneous flags\n");
	printf("-h\tprint this help and exit\n");
	printf("-q\tquiet mode, don't print anything\n");
	printf("-v\tverbose mode (list contents of /proc/<pid>/fd)\n");

}

int main(int argc, char *argv[])
{
	int ret;
        int opt;
	int pipefd[2];

	max_msgs = 4;
	while ((opt = getopt(argc, argv, cli_flags)) != -1) {
		switch (opt) {
		case 'c': cflag++; break;
		case 'd': dflag++; max_msgs += 4; break;
		case 'h': usage(argv[0]); return 0;
		case 'l': lflag++; break;
		case 'n': nflag++; break;
		case 'o': oflag++; max_msgs += 4; break;
		case 'q': qflag++; vflag = 0;break;
		case 'r': rflag++; break;
		case 'v': vflag++; qflag = 0; break;
		default: usage(argv[0]); return 1;
		}
	}

	setbuf(stdout, NULL);
	setbuf(stderr, NULL);
	mkdir_safe(IMG_DIR, 0700);

	pipe_safe(pipefd);
	child_pid = fork_safe();
	if (child_pid > 0) {
		parent_pid = getpid();

		signal_safe(SIGCHLD, chld_handler);
		prctl_safe(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0);

		close_safe(pipefd[WRITE_FD]);

		ret = parent(pipefd);
	} else {
		/* child */
		int dupfd = -1;
		int openfd = -1;
		int logfd;

		child_pid = getpid();

		close_safe(pipefd[READ_FD]);
		setsid();
		logfd = open_safe(OLD_LOG_FILE, O_WRONLY | O_APPEND | O_CREAT);
		dup2_safe(logfd, 1);
		dup2_safe(logfd, 2);
		close(logfd);
		close(0);

		/* open a regular file and move it to CLASH_FD */
		if (cflag)
			move_fd(open_safe(OLD_LOG_FILE, O_WRONLY | O_APPEND | O_CREAT), CLASH_FD);

		/* open additional descriptors on the pipe and use them all */
		if (dflag)
			dupfd = dup_safe(pipefd[WRITE_FD]);
		if (oflag) {
			char buf[128];
			snprintf(buf, sizeof buf, "/proc/self/fd/%d", pipefd[WRITE_FD]);
			openfd = open_safe(buf, O_WRONLY);
		}

		ret = child(pipefd, dupfd, openfd);
	}

	return ret;
}

/*
 * Parent reads message from its pipe with the child.
 * After a couple of messages, it checkpoints the child
 * which causes the child to exit.  Parent then creates
 * a new pipe and restores the child.
 */
int parent(int *pipefd)
{
	char buf[32];
	char old_pipe[32];
	int nread;

	nread = 0;
	while (max_forks <= MAX_FORKS) {
		if (read_safe(pipefd[READ_FD], buf, sizeof buf) == 0)
			continue;
		nread++;
		if (vflag && nread == 1)
			ls_proc_fd(-1);

		if (!qflag) {
			printf("%s read %s from %s\n", who(0), buf,
				pipe_name(pipefd[READ_FD]));
		}

		if (nread == (max_msgs / 2)) {
			checkpoint_child(child_pid, pipefd);

			if (!nflag) {
				/* save the old pipe's name before closing it */
				snprintf(old_pipe, sizeof old_pipe, "%s",
					pipe_name(pipefd[READ_FD]));
				close_safe(pipefd[READ_FD]);

				/* create a new one */
				if (!qflag)
					printf("%s creating a new pipe\n", who(0));
				pipe_safe(pipefd);
			}
			restore_child(pipefd, old_pipe);
		}
	}

	return 0;
}

/*
 * Child sends a total of max_messages messages to its
 * parent, half before checkpoint and half after restore.
 */
int child(int *pipefd, int dupfd, int openfd)
{
	int i;
	int fd;
	int num_wfds;
	struct timespec req = { 1, 0 };

	/*
	 * Count the number of pipe descriptors we'll be
	 * writing to.  At least 1 (for pipefd[WRITE_FD])
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
		case 0: fd = pipefd[WRITE_FD]; break;
		case 1: fd = dflag ? dupfd : openfd; break;
		case 2: fd = openfd; break;
		}

		write_to_fd(fd, pipe_name(pipefd[WRITE_FD]), i+1, 0);
		if (cflag)
			write_to_fd(CLASH_FD, "log file", i+1, 1);

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
		if (!qflag)
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
		if (!qflag) {
			printf("%s %s exited with status %d\n", who(0),
				who(pid), status); 
		}
		/* if child exited successfully, we're done */
		if (status == 0)
			exit(0);
		/* checkpoint kills the child */
		if (status != 9)
			exit(status);
	}
}

void checkpoint_child(int child_pid, int *pipefd)
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
		if (!qflag) {
			printf("%s %s exited with status %d\n", who(0),
				who(pid), status);
		}
		if (status)
			exit(status);
	} else {
		close(pipefd[READ_FD]);
		criu_dump_pid = getpid();
		execv_safe(CRIU_BINARY, dump_argv, 0);
	}
}

void restore_child(int *new_pipefd, char *old_pipe_name)
{
	char buf[64];

	criu_restore_pid = fork_safe();
	if (criu_restore_pid > 0) {
		int status;
		pid_t pid;

		if (!nflag)
			close_safe(new_pipefd[WRITE_FD]);

		pid = waitpid_safe(criu_restore_pid, &status, 0, 3);
		if (WIFEXITED(status))
			status = WEXITSTATUS(status);
		if (!qflag) {
			printf("%s %s exited with status %d\n", who(0),
				who(pid), status);
		}
		if (status)
			exit(status);
	} else {
		criu_restore_pid = getpid();

		if (!nflag) {
			/*
			 * We should close the read descriptor of the new pipe
			 * and use its write descriptor to call criu restore.
			 * But if rflag was set (for testing purposes), use the
			 * read descriptor which should cause the application to
			 * fail.
			 *
			 * Regardless of read or write descriptor, move it to a
			 * clashing fd to test inherit fd clash resolve code.
			 */
			if (rflag)
				move_fd(new_pipefd[READ_FD], CLASH_FD);
			else {
				close_safe(new_pipefd[READ_FD]);
				move_fd(new_pipefd[WRITE_FD], CLASH_FD);
			}

			/* --inherit-fd fd[CLASH_FD]:pipe[xxxxxx] */
			snprintf(inh_pipe_opt, sizeof inh_pipe_opt,
				"%s", INHERIT_FD_OPTION);
			snprintf(inh_pipe_arg, sizeof inh_pipe_arg, "fd[%d]:%s",
				CLASH_FD, old_pipe_name);

			if (lflag) {
				/* create a new log file to replace the old one */
				int filefd = open_safe(NEW_LOG_FILE, O_WRONLY | O_APPEND | O_CREAT);

				/* --inherit-fd fd[x]:tmp/oldlog */
				snprintf(inh_file_opt, sizeof inh_file_opt,
					"%s", INHERIT_FD_OPTION);
				snprintf(inh_file_arg, sizeof inh_file_arg,
					"fd[%d]:%s", filefd, OLD_LOG_FILE + 1);

				restore_argv[12] = inh_file_opt;
			} else
				restore_argv[12] = NULL;
			restore_argv[10] = inh_pipe_opt;
		} else
			restore_argv[10] = NULL;

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
	if (!qflag)
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

	if (qflag)
		return;

	if (fd == -1)
		snprintf(cmd, sizeof cmd, "ls -l /proc/%d/fd", getpid());
	else
		snprintf(cmd, sizeof cmd, "ls -l /proc/%d/fd/%d", getpid(), fd);
	printf("%s %s\n", who(0), cmd);
	system(cmd);
}

char *pipe_name(int fd)
{
	static char pipe_name[64];
	char path[64];

	snprintf(path, sizeof path, "/proc/self/fd/%d", fd);
	if (readlink(path, pipe_name, sizeof pipe_name) == -1)
		die("readlink: path=%s", path);
	return pipe_name;
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

void pipe_safe(int pipefd[2])
{
	if (pipe(pipefd) == -1)
		die("pipe: %p", pipefd);
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

	if (!qflag) {
		printf("\n%s ", who(0));
		for (i = 0; argv[i] != NULL; i++)
			printf("%s ", argv[i]);
		printf("\n");
	}

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
