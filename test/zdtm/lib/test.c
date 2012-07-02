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

#include "zdtmtst.h"

static volatile sig_atomic_t sig_received = 0;

static void sig_hand(int signo)
{
	sig_received = signo;
}

static char *outfile;
TEST_OPTION(outfile, string, "output file", 1);
static char *pidfile;
TEST_OPTION(pidfile, string, "file to store pid", 1);

static pid_t master_pid = 0;

int proc_id = 0;
static int proc_id_cur = 0;

int test_fork_id(int id)
{
	pid_t pid = fork();
	if (id < 0)
		id = ++proc_id_cur;
	if (pid == 0)
		proc_id = id;
	return pid;
}

static void test_fini(void)
{
	extern void dump_msg(const char *);
	dump_msg(outfile);
	if (getpid() == master_pid)
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
}

static void redir_stdfds()
{
	int nullfd;

	nullfd = open("/dev/null", O_RDWR);
	if (nullfd < 0) {
		err("Can't open /dev/null: %m\n");
		exit(1);
	}

	dup2(nullfd, 0);
	dup2(nullfd, 1);
	dup2(nullfd, 2);
	if (nullfd > 2)
		close(nullfd);
}

void test_init(int argc, char **argv)
{
	extern void parseargs(int, char **);

	pid_t pid;
	static FILE *pidf;
	struct sigaction sa = {
		.sa_handler	= sig_hand,
		.sa_flags	= SA_RESTART,
	};
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

	setup_outfile();
	redir_stdfds();

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

		if (sig_received == SIGCHLD) {
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

	/* record the test pid to remember the ownership of the pidfile */
	master_pid = getpid();

	fclose(pidf);

	sa.sa_handler = SIG_DFL;
	if (sigaction(SIGCHLD, &sa, NULL)) {
		err("Can't reset SIGCHLD handler: %m\n");
		exit(1);
	}

	if (setsid() < 0) {
		err("Can't become session group leader: %m\n");
		exit(1);
	}

	srand48(time(NULL));	/* just in case we need it */
}

#define STACK_SIZE	(8 * 4096)

struct zdtm_clone_arg {
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
	void *stack;

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

	setup_outfile();
	redir_stdfds();

	pidf = fopen(pidfile, "wx");
	if (!pidf) {
		err("Can't create pid file %s: %m\n", pidfile);
		exit(1);
	}

	stack = mmap(NULL, STACK_SIZE, PROT_WRITE | PROT_READ,
			MAP_PRIVATE | MAP_GROWSDOWN | MAP_ANONYMOUS, -1, 0);
	if (stack == MAP_FAILED) {
		err("Can't map stack\n");
		exit(1);
	}

	ca.pidf = pidf;
	ca.fn = fn;
	ca.argc = argc;
	ca.argv = argv;
	pid = clone(do_test_fn, stack + STACK_SIZE, clone_flags | SIGCHLD, &ca);
	if (pid < 0) {
		err("Daemonizing failed: %m\n");
		exit(1);
	}

	/* parent will exit when the child is ready */
	test_waitsig();

	if (sig_received == SIGCHLD) {
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
	return !sig_received;
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
}
