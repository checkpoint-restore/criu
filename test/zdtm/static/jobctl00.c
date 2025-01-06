#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <string.h>
#include <pty.h>

#include "zdtmtst.h"

const char *test_doc = "Check that job control migrates correctly";
const char *test_author = "Roman Kagan <rkagan@parallels.com>";

#define JOBS_DEF 8
#define JOBS_MAX 64
unsigned int num_jobs = JOBS_DEF;
TEST_OPTION(num_jobs, uint,
	    "# \"jobs\" in a \"shell\" "
	    "(default " __stringify(JOBS_DEF) ", max " __stringify(JOBS_MAX) ")",
	    0);

#define PROCS_DEF 4
unsigned int num_procs = PROCS_DEF;
TEST_OPTION(num_procs, uint,
	    "# processes in a \"job\" "
	    "(default " __stringify(PROCS_DEF) ")",
	    0);

static const char wr_string[] = "All you need is love!\n";
static const char rd_string[] = "We all live in a yellow submarine\n";
static const char susp_char = '\032'; /* ^Z */

static volatile sig_atomic_t signo = 0;

static void record_sig(int sig)
{
	signo = sig;
}

static void record_and_raise_sig(int sig)
{
	signo = sig;
	signal(sig, SIG_DFL);
	raise(sig);
}

static int wait4sig(int sig)
{
	sigset_t mask, oldmask;
	sigemptyset(&mask);
	sigaddset(&mask, sig);
	sigaddset(&mask, SIGCHLD); /* to see our children die */

	sigprocmask(SIG_BLOCK, &mask, &oldmask);
	while (!signo)
		sigsuspend(&oldmask);
	sigprocmask(SIG_UNBLOCK, &mask, NULL);

	return signo != sig;
}

static int is_fg(void)
{
	pid_t pgid = getpgrp();
	pid_t tcpgid = tcgetpgrp(1);

	return (pgid != -1) && (pgid == tcpgid);
}

static int reader(int sig)
{
	char str[sizeof(rd_string) + 1];
	return read(0, str, sizeof(str)) < 0 || strcmp(str, rd_string);
}

static int post_reader(int fd)
{
	if (write(fd, rd_string, sizeof(rd_string) - 1) < 0) {
		fail("write failed");
		return -1;
	}
	return 0;
}

static int writer(int sig)
{
	return write(1, wr_string, sizeof(wr_string) - 1) < 0;
}

static int post_writer(int fd)
{
	char str[sizeof(wr_string) + 1];
	if (read(0, str, sizeof(str)) < 0) {
		fail("read failed");
		return -1;
	}
	/*
	if (strcmp(str, wr_string)) {
		fail("read string mismatch");
		return -1;
	}
	*/
	return 0;
}

static struct job_type {
	int sig;
	int (*action)(int sig);
	int (*post)(int fd);
} job_types[] = {
	{ SIGTTOU, writer, post_writer },
	{ SIGTTIN, reader, post_reader },
	{ SIGCONT, wait4sig, NULL },
};

static int process(int (*action)(int), int sig)
{
	int ret;
	if (is_fg()) /* we must be in background on entry */
		return 1;

	if (signal(sig, record_and_raise_sig) == SIG_ERR)
		return 2;

	kill(getppid(), SIGUSR2); /* tell the parent we're ready */

	ret = action(sig); /* will be busy doing nothing for the duration of migration */
	if (ret)
		return 3;

	if (!is_fg()) /* we must be in foreground now */
		return 4;

	ret = signo != sig; /* have we got the desired signal? */

	test_waitsig();
	return ret;
}

static int job(int (*action)(int), int sig)
{
	int i;

	if (setpgrp() < 0)
		return 1;

	for (i = num_procs; i; i--) {
		pid_t pid = fork();
		if (pid < 0)
			kill(0, SIGKILL); /* kill the whole job */

		if (pid == 0)
			/* the last is worker, others are sleepers */
			exit(process(i == 1 ? action : wait4sig, sig));

		/* wait for the child to grow up before going to next one
		 * ignore return code as the child may get stopped and SIGCHILD
		 * us */
		wait4sig(SIGUSR2);
		signo = 0; /* rearm sighandler */
	}

	kill(getppid(), SIGUSR2); /* tell the parent we're ready */

	/* we (or our children) will get suspended somehow here, so the rest
	 * will hopefully happen after migration */
	for (i = num_procs; i; i--) {
		int ret;
		wait(&ret);
		if (!WIFEXITED(ret) || WEXITSTATUS(ret))
			kill(0, SIGKILL);
	}

	return 0;
}

static int make_pty_pair(int *fdmaster, int *fdslave)
{
	struct termios tio;

	if (openpty(fdmaster, fdslave, NULL, &tio, NULL) < 0)
		return -1;

	if (ioctl(*fdslave, TIOCSCTTY, NULL) < 0)
		return -1;

	tio.c_lflag |= (ICANON | ISIG | TOSTOP);
	if (tcsetattr(*fdslave, TCSANOW, &tio) < 0)
		return -1;
	return 0;
}

int start_jobs(pid_t *jobs, int njobs, int fdmaster, int fdslave)
{
	int i;

	/* the children will signal readiness via SIGUSR2 or get stopped (or
	 * exit :) and signal that via SIGCHLD */
	if (signal(SIGUSR2, record_sig) == SIG_ERR || signal(SIGCHLD, record_sig) == SIG_ERR) {
		pr_perror("can't install signal handler");
		return -1;
	}

	for (i = 0; i < njobs; i++) {
		int jtno = i % (sizeof(job_types) / sizeof(job_types[0]));

		jobs[i] = fork();
		if (jobs[i] < 0) { /* we're busted - bail out */
			pr_perror("fork failed");
			goto killout;
		}

		if (jobs[i] == 0) {
			close(fdmaster);
			dup2(fdslave, 0);
			dup2(fdslave, 1);
			dup2(fdslave, 2);
			close(fdslave);

			exit(job(job_types[jtno].action, job_types[jtno].sig));
		}

		/* wait for the child to grow up before proceeding */
		wait4sig(SIGUSR2);
		signo = 0; /* rearm sighandler */
	}

	return 0;
killout:
	for (; i >= 0; i--)
		kill(-jobs[i], SIGKILL);
	return -1;
}

int finish_jobs(pid_t *jobs, int njobs, int fdmaster, int fdslave)
{
	int i;

	for (i = num_jobs; i--;) {
		int ret;
		int jtno = i % (sizeof(job_types) / sizeof(job_types[0]));

		if (tcsetpgrp(fdslave, jobs[i]) < 0) {
			fail("can't bring a job into foreground");
			goto killout;
		}

		kill(-jobs[i], SIGCONT);

		if (job_types[jtno].post && job_types[jtno].post(fdmaster))
			goto killout;

		kill(-jobs[i], SIGTERM);

		waitpid(jobs[i], &ret, 0);
		if (!WIFEXITED(ret) || WEXITSTATUS(ret)) {
			fail("job didn't exit cleanly: %d", ret);
			goto killout;
		}
	}
	return 0;
killout:
	for (; i >= 0; i--)
		kill(-jobs[i], SIGKILL);
	return -1;
}

int main(int argc, char **argv)
{
	int fdmaster, fdslave;
	pid_t jobs[JOBS_MAX] = {};

	test_init(argc, argv);

	if (num_jobs > JOBS_MAX) {
		pr_perror("%d jobs is too many", num_jobs);
		exit(1);
	}

	if (make_pty_pair(&fdmaster, &fdslave) < 0) {
		pr_perror("can't make pty pair");
		exit(1);
	}

	sleep(30);

	if (start_jobs(jobs, num_jobs, fdmaster, fdslave)) {
		pr_perror("failed to start jobs");
		exit(1);
	}

	test_daemon();
	test_waitsig();

	if (finish_jobs(jobs, num_jobs, fdmaster, fdslave))
		fail("failed to finish jobs");
	else
		pass();

	return 0;
}
