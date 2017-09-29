#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <signal.h>

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <pthread.h>

#include "zdtmtst.h"

#define gettid()	pthread_self()

const char *test_doc	= "Create a few pthreads and test TLS + blocked signals\n";
const char *test_author	= "Cyrill Gorcunov <gorcunov@openvz.org";

static __thread struct tls_data_s {
	char		*rand_string[10];
	sigset_t	blk_sigset;
} tls_data;

static task_waiter_t t1;
static task_waiter_t t2;

static char *decode_signal(const sigset_t *s, char *buf)
{
	buf[0] = '\0';

#define COLLECT(sig)						\
	do {							\
		if (sigismember(s, sig))			\
			strcat(buf, #sig " ");			\
	} while (0)

	COLLECT(SIGHUP); COLLECT(SIGINT); COLLECT(SIGQUIT); COLLECT(SIGILL); COLLECT(SIGTRAP);
	COLLECT(SIGABRT); COLLECT(SIGIOT); COLLECT(SIGBUS); COLLECT(SIGFPE); COLLECT(SIGKILL);
	COLLECT(SIGUSR1); COLLECT(SIGSEGV); COLLECT(SIGUSR2); COLLECT(SIGPIPE); COLLECT(SIGALRM);
	COLLECT(SIGTERM); COLLECT(SIGSTKFLT); COLLECT(SIGCHLD); COLLECT(SIGCONT); COLLECT(SIGSTOP);
	COLLECT(SIGTSTP); COLLECT(SIGTTIN); COLLECT(SIGTTOU); COLLECT(SIGURG); COLLECT(SIGXCPU);
	COLLECT(SIGXFSZ); COLLECT(SIGVTALRM); COLLECT(SIGPROF); COLLECT(SIGWINCH); COLLECT(SIGIO);
	COLLECT(SIGPOLL); COLLECT(SIGPWR); COLLECT(SIGSYS);
#undef COLLECT

	return buf;
}

static void __show_sigset(int line, const sigset_t *s)
{
	char buf[sizeof(sigset_t) * 2 + 1] = { };

	decode_signal(s, buf);
	test_msg("sigset at %4d: %s\n", line, buf);
}

#define show_sigset(set)	__show_sigset(__LINE__, set)

static void *ch_thread_2(void *arg)
{
	char __tls_data[sizeof(tls_data.rand_string)] = "XM5o:?B*[a";
	int *results_map = arg;
	sigset_t blk_sigset = { };
	sigset_t new = { };

	memcpy(tls_data.rand_string, __tls_data, sizeof(tls_data.rand_string));

	sigemptyset(&blk_sigset);
	pthread_sigmask(SIG_SETMASK, NULL, &blk_sigset);
	sigaddset(&blk_sigset, SIGFPE);
	pthread_sigmask(SIG_SETMASK, &blk_sigset, NULL);
	memcpy(&tls_data.blk_sigset, &blk_sigset, sizeof(tls_data.blk_sigset));

	show_sigset(&blk_sigset);
	show_sigset(&tls_data.blk_sigset);

	task_waiter_complete(&t2, 1);
	task_waiter_wait4(&t2, 2);

	if (memcmp(tls_data.rand_string, __tls_data, sizeof(tls_data.rand_string))) {
		pr_perror("Failed to restore tls_data.rand_string in thread 2");
		results_map[2] = -1;
	} else
		results_map[2] = 1;

	if (memcmp(&tls_data.blk_sigset, &blk_sigset, sizeof(tls_data.blk_sigset))) {
		pr_perror("Failed to restore tls_data.blk_sigset in thread 2");
		results_map[4] = -1;
	} else
		results_map[4] = 1;

	pthread_sigmask(SIG_SETMASK, NULL, &new);
	if (memcmp(&tls_data.blk_sigset, &new, sizeof(tls_data.blk_sigset))) {
		pr_perror("Failed to restore blk_sigset in thread 2");
		results_map[6] = -1;

		show_sigset(&tls_data.blk_sigset);
		show_sigset(&new);
	} else
		results_map[6] = 1;

	return NULL;
}

static void *ch_thread_1(void *arg)
{
	char __tls_data[sizeof(tls_data.rand_string)] = "pffYQSBo?6";
	int *results_map = arg;
	sigset_t blk_sigset = { };
	sigset_t new = { };

	memcpy(tls_data.rand_string, __tls_data, sizeof(tls_data.rand_string));

	sigemptyset(&blk_sigset);
	pthread_sigmask(SIG_SETMASK, NULL, &blk_sigset);
	sigaddset(&blk_sigset, SIGWINCH);
	sigaddset(&blk_sigset, SIGALRM);
	pthread_sigmask(SIG_SETMASK, &blk_sigset, NULL);
	memcpy(&tls_data.blk_sigset, &blk_sigset, sizeof(tls_data.blk_sigset));

	show_sigset(&blk_sigset);
	show_sigset(&tls_data.blk_sigset);

	task_waiter_complete(&t1, 1);
	task_waiter_wait4(&t1, 2);

	if (memcmp(tls_data.rand_string, __tls_data, sizeof(tls_data.rand_string))) {
		pr_perror("Failed to restore tls_data.rand_string in thread 1");
		results_map[1] = -1;
	} else
		results_map[1] = 1;

	if (memcmp(&tls_data.blk_sigset, &blk_sigset, sizeof(tls_data.blk_sigset))) {
		pr_perror("Failed to restore tls_data.blk_sigset in thread 1");
		results_map[3] = -1;
	} else
		results_map[3] = 1;

	sigemptyset(&new);
	pthread_sigmask(SIG_SETMASK, NULL, &new);
	if (memcmp(&tls_data.blk_sigset, &new, sizeof(tls_data.blk_sigset))) {
		pr_perror("Failed to restore blk_sigset in thread 1");
		results_map[5] = -1;

		show_sigset(&tls_data.blk_sigset);
		show_sigset(&new);
	} else
		results_map[5] = 1;

	return NULL;
}

int main(int argc, char *argv[])
{
	pthread_t thread_1, thread_2;
	int *results_map;
	int rc1, rc2;

	test_init(argc, argv);

	task_waiter_init(&t1);
	task_waiter_init(&t2);

	test_msg("%s pid %d\n", argv[0], getpid());

	results_map = mmap(NULL, 1024, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if ((void *)results_map == MAP_FAILED) {
		fail("Can't map");
		exit(1);
	}

	rc1 = pthread_create(&thread_1, NULL, &ch_thread_1, results_map);
	rc2 = pthread_create(&thread_2, NULL, &ch_thread_2, results_map);

	if (rc1 | rc2) {
		fail("Can't pthread_create");
		exit(1);
	}

	test_msg("Waiting until all threads are created\n");

	task_waiter_wait4(&t1, 1);
	task_waiter_wait4(&t2, 1);

	test_daemon();
	test_waitsig();

	task_waiter_complete(&t1, 2);
	task_waiter_complete(&t2, 2);

	test_msg("Waiting while all threads are joined\n");
	pthread_join(thread_1, NULL);
	pthread_join(thread_2, NULL);

	if (results_map[1] == 1 &&
	    results_map[2] == 1 &&
	    results_map[3] == 1 &&
	    results_map[4] == 1 &&
	    results_map[5] == 1 &&
	    results_map[6] == 1)
		pass();
	else
		fail();

	return 0;
}
