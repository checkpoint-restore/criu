#define _GNU_SOURCE
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <stdlib.h>
#include <signal.h>
#include <time.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sched.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <string.h>
#include <sys/prctl.h>
#include <grp.h>

#include "zdtmtst.h"
#include "lock.h"
#include "ns.h"

futex_t sig_received;

static void sig_hand(int signo)
{
	futex_set_and_wake(&sig_received, signo);
}

static char *outfile;
TEST_OPTION(outfile, string, "output file", 1);
char *pidfile;
TEST_OPTION(pidfile, string, "file to store pid", 1);

static pid_t master_pid = 0;

int test_fork_id(int id)
{
	return fork();
}

#define INPROGRESS ".inprogress"
static void test_fini(void)
{
	char path[PATH_MAX];

	if (getpid() != master_pid)
		return;

	snprintf(path, sizeof(path), "%s%s", outfile, INPROGRESS);
	rename(path, outfile);

	unlink(pidfile);
}

static void setup_outfile()
{
	if (!access(outfile, F_OK) || errno != ENOENT) {
		fprintf(stderr, "Output file %s appears to exist, aborting\n",
			outfile);
		exit(1);
	}

	if (atexit(test_fini)) {
		fprintf(stderr, "Can't register exit function\n");
		exit(1);
	}
	if (test_log_init(outfile, INPROGRESS))
		exit(1);
}

static void redir_stdfds()
{
	int nullfd;

	nullfd = open("/dev/null", O_RDWR);
	if (nullfd < 0) {
		pr_perror("Can't open /dev/null");
		exit(1);
	}

	dup2(nullfd, STDIN_FILENO);
	if (nullfd > 2)
		close(nullfd);
}

void test_ext_init(int argc, char **argv)
{
	parseargs(argc, argv);
	if (test_log_init(outfile, ".external"))
		exit(1);
}

int write_pidfile(int pid)
{
	int fd;

	fd = open(pidfile, O_CREAT | O_EXCL | O_WRONLY, 0666);
	if (fd == -1) {
		fprintf(stderr, "Can't create the file %s: %m\n", pidfile);
		return -1;
	}
	if (dprintf(fd, "%d", pid) == -1) {
		fprintf(stderr, "Can't write in the file %s: %m\n", pidfile);
		return -1;
	}

	close(fd);

	return 0;
}

void test_init(int argc, char **argv)
{
	pid_t pid;
	char *val;
	struct sigaction sa = {
		.sa_handler	= sig_hand,
		.sa_flags	= SA_RESTART,
	};
	sigemptyset(&sa.sa_mask);

	parseargs(argc, argv);

	val = getenv("ZDTM_NEWNS");
	if (val) {
		if (!strcmp(val, "1")) {
			ns_create(argc, argv);
			exit(1);
		}

		if (!strcmp(val, "2")) {
			test_log_init(outfile, "ns");
			redir_stdfds();
			ns_init(argc, argv);
		}
	}

	val = getenv("ZDTM_GROUPS");
	if (val) {
		char *tok = NULL;
		unsigned int size = 0, groups[NGROUPS_MAX];

		tok = strtok(val, " ");
		while (tok) {
			size++;
			groups[size - 1] = atoi(tok);
			tok = strtok(NULL, " ");
		}

		if (setgroups(size, groups)) {
			fprintf(stderr, "Can't set groups: %m");
			exit(1);
		}
	}

	val = getenv("ZDTM_GID");
	if (val && (setgid(atoi(val)) == -1)) {
		fprintf(stderr, "Can't set gid: %m");
		exit(1);
	}

	val = getenv("ZDTM_UID");
	if (val && (setuid(atoi(val)) == -1)) {
		fprintf(stderr, "Can't set gid: %m");
		exit(1);
	}

	if (prctl(PR_SET_DUMPABLE, 1)) {
		fprintf(stderr, "Can't set the dumpable flag");
		exit(1);
	}

	if (sigaction(SIGTERM, &sa, NULL)) {
		fprintf(stderr, "Can't set SIGTERM handler: %m\n");
		exit(1);
	}

	if (sigaction(SIGCHLD, &sa, NULL)) {
		fprintf(stderr, "Can't set SIGCHLD handler: %m\n");
		exit(1);
	}

	setup_outfile();
	redir_stdfds();

	pid = fork();
	if (pid < 0) {
		pr_perror("Daemonizing failed");
		exit(1);
	}

	if (pid) {	/* parent will exit when the child is ready */
		test_waitsig();

		if (futex_get(&sig_received) == SIGCHLD) {
			int ret;
			if (waitpid(pid, &ret, 0) != pid) {
				pr_perror("Unable to wait %d, pid");
				exit(1);
			}

			if (WIFEXITED(ret)) {
				pr_err("Test exited unexpectedly with code %d\n", WEXITSTATUS(ret));
				exit(1);
			}
			if (WIFSIGNALED(ret)) {
				pr_err("Test exited on unexpected signal %d\n", WTERMSIG(ret));
				exit(1);
			}
		}

		if (write_pidfile(pid))
			exit(1);

		_exit(0);
	}

	if (setsid() < 0) {
		pr_perror("Can't become session group leader");
		exit(1);
	}

	/* record the test pid to remember the ownership of the pidfile */
	master_pid = getpid();

	sa.sa_handler = SIG_DFL;
	if (sigaction(SIGCHLD, &sa, NULL)) {
		pr_perror("Can't reset SIGCHLD handler");
		exit(1);
	}

	srand48(time(NULL));	/* just in case we need it */
}

void test_daemon()
{
	pid_t ppid;

	ppid = getppid();
	if (ppid <= 1) {
		pr_perror("Test orphaned");
		goto out;
	}

	if (kill(ppid, SIGTERM))
		goto out;
	return;
out:
	/* kill out our process group for safety */
	kill(0, SIGKILL);
	exit(1);
}

int test_go(void)
{
	return !futex_get(&sig_received);
}

void test_waitsig(void)
{
	futex_wait_while(&sig_received, 0);
}
