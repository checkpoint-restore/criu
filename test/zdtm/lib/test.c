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

void setup_outfile()
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
		err("Can't open /dev/null: %m\n");
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

void test_init(int argc, char **argv)
{
	pid_t pid;
	static FILE *pidf;
	char *val;
	struct sigaction sa = {
		.sa_handler	= sig_hand,
		.sa_flags	= SA_RESTART,
	};
	sigemptyset(&sa.sa_mask);

	parseargs(argc, argv);

	val = getenv("ZDTM_NEWNS");
	if (val) {
		unsetenv("ZDTM_NEWNS");
		ns_create(argc, argv);
		exit(1);
	}

	val = getenv("ZDTM_EXE");
	if (val) {
		test_log_init(outfile, "ns");
		redir_stdfds();
		unsetenv("ZDTM_EXE");
		ns_init(argc, argv);
		exit(1);
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

	if (getenv("ZDTM_REEXEC"))
		goto skip_pid;

	pidf = fopen(pidfile, "wx");
	if (!pidf) {
		err("Can't create pid file %s: %m\n", pidfile);
		exit(1);
	}

	pid = fork();
	if (pid < 0) {
		err("Daemonizing failed: %m\n");
		exit(1);
	}

	if (pid) {	/* parent will exit when the child is ready */
		test_waitsig();

		if (futex_get(&sig_received) == SIGCHLD) {
			int ret;
			waitpid(pid, &ret, 0);

			if (WIFEXITED(ret)) {
				err("Test exited with unexpectedly with code %d\n", WEXITSTATUS(ret));
				exit(0);
			}
			if (WIFSIGNALED(ret)) {
				err("Test exited on unexpected signal %d\n", WTERMSIG(ret));
				exit(0);
			}
		}

		fprintf(pidf, "%d\n", pid);
		fclose(pidf);
		_exit(0);
	}

	fclose(pidf);

	if (setsid() < 0) {
		err("Can't become session group leader: %m\n");
		exit(1);
	}

skip_pid:
	/* record the test pid to remember the ownership of the pidfile */
	master_pid = getpid();

	sa.sa_handler = SIG_DFL;
	if (sigaction(SIGCHLD, &sa, NULL)) {
		err("Can't reset SIGCHLD handler: %m\n");
		exit(1);
	}

	srand48(time(NULL));	/* just in case we need it */
}

#define STACK_SIZE	4096

struct zdtm_clone_arg {
	char stack[STACK_SIZE];
	char stack_ptr[0];
	FILE *pidf;
	int argc;
	char **argv;
	int (*fn)(int argc, char **argv);
};

static int do_test_fn(void *_arg)
{
	struct zdtm_clone_arg *ca = _arg;
	struct sigaction sa = {
		.sa_handler	= SIG_DFL,
		.sa_flags	= SA_RESTART,
	};

	/* record the test pid to remember the ownership of the pidfile */
	master_pid = getpid();

	fclose(ca->pidf);

	sigemptyset(&sa.sa_mask);
	if (sigaction(SIGCHLD, &sa, NULL)) {
		err("Can't reset SIGCHLD handler: %m\n");
		exit(1);
	}

	if (setsid() < 0) {
		err("Can't become session group leader: %m\n");
		exit(1);
	}

	srand48(time(NULL));	/* just in case we need it */

	if (ca->fn(ca->argc, ca->argv))
		exit(1);
	exit(0);
}

void test_init_ns(int argc, char **argv, unsigned long clone_flags,
		  int (*fn)(int , char **))
{
	extern void parseargs(int, char **);

	pid_t pid;
	static FILE *pidf;
	struct sigaction sa = {
		.sa_handler	= sig_hand,
		.sa_flags	= SA_RESTART,
	};
	struct zdtm_clone_arg ca;

	sigemptyset(&sa.sa_mask);

	if (sigaction(SIGTERM, &sa, NULL)) {
		fprintf(stderr, "Can't set SIGTERM handler: %m\n");
		exit(1);
	}

	if (sigaction(SIGCHLD, &sa, NULL)) {
		fprintf(stderr, "Can't set SIGCHLD handler: %m\n");
		exit(1);
	}

	parseargs(argc, argv);

	/* setup_outfile() should be called in a target mount namespace */
	if (!(clone_flags & CLONE_NEWNS))
		setup_outfile();
	redir_stdfds();

	pidf = fopen(pidfile, "wx");
	if (!pidf) {
		err("Can't create pid file %s: %m\n", pidfile);
		exit(1);
	}

	ca.pidf = pidf;
	ca.fn = fn;
	ca.argc = argc;
	ca.argv = argv;
	pid = clone(do_test_fn, ca.stack_ptr, clone_flags | SIGCHLD, &ca);
	if (pid < 0) {
		err("Daemonizing failed: %m\n");
		exit(1);
	}

	/* parent will exit when the child is ready */
	test_waitsig();

	if (futex_get(&sig_received) == SIGCHLD) {
		int ret;
		waitpid(pid, &ret, 0);

		if (WIFEXITED(ret)) {
			err("Test exited with unexpectedly with code %d\n", WEXITSTATUS(ret));
			exit(0);
		}
		if (WIFSIGNALED(ret)) {
			err("Test exited on unexpected signal %d\n", WTERMSIG(ret));
			exit(0);
		}
	}

	fprintf(pidf, "%d\n", pid);
	fclose(pidf);
	_exit(0);
}

void test_daemon()
{
	pid_t ppid;

	ppid = getppid();
	if (ppid <= 1) {
		err("Test orphaned\n");
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
