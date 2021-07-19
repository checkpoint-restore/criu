#include <signal.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <pthread.h>
#include <string.h>
#include <limits.h>
#include <sys/wait.h>

#include "zdtmtst.h"

const char *test_doc = "Check pending signals";
const char *test_author = "Andrew Vagin <avagin@parallels.com>";

static pid_t child;
static int numsig;

#define TESTSIG	  (SIGRTMAX)
#define THREADSIG (SIGRTMIN)
static siginfo_t share_infos[2];
static siginfo_t self_infos[64]; /* self */
static siginfo_t thread_infos[3]; /* thread */
static int share_nr;
static int self_nr;
static int thread_nr;

#ifndef offsetof
#define offsetof(TYPE, MEMBER) ((size_t) & ((TYPE *)0)->MEMBER)
#endif

/* cr_siginfo is declared to get an offset of _sifields */
union cr_siginfo {
	struct {
		int si_signo;
		int si_errno;
		int si_code;

		union {
			int _pad[10];
			/* ... */
		} _sifields;
	} _info;
	siginfo_t info;
};
typedef union cr_siginfo cr_siginfo_t;

#define siginf_body(s) (&((cr_siginfo_t *)(s))->_info._sifields)

/*
 * The kernel puts only relevant union member when signal arrives,
 * leaving _si_fields to be filled with junk from stack. Check only
 * first 12 bytes:
 *	// POSIX.1b signals.
 *	struct
 *	  {
 *	    __pid_t si_pid;	// Sending process ID.
 *	    __uid_t si_uid;	// Real user ID of sending process.
 *	    sigval_t si_sigval;	// Signal value.
 *	  } _rt;
 * Look at __copy_siginfo_to_user32() for more information.
 */
#define _si_fields_sz  12
#define siginfo_filled (offsetof(cr_siginfo_t, _info._sifields) + _si_fields_sz)

static pthread_mutex_t exit_lock;
static pthread_mutex_t init_lock;

static void sig_handler(int signal, siginfo_t *info, void *data)
{
	uint32_t crc;

	test_msg("signo=%d si_code=%x\n", signal, info->si_code);

	if (test_go()) {
		pr_perror("The signal is received before unlocking");
		return;
	}

	switch (signal) {
	case SIGCHLD:
		if ((info->si_code & CLD_EXITED) && (info->si_pid == child) && (info->si_status == 5))
			numsig++;
		else {
			fail("Wrong siginfo");
			exit(1);
		}
		return;
	}

	if (TESTSIG == signal || THREADSIG == signal) {
		siginfo_t *src;

		if (signal == TESTSIG) {
			src = &share_infos[share_nr];
			share_nr++;
		} else if (getpid() == syscall(SYS_gettid)) {
			src = &self_infos[self_nr];
			self_nr++;
		} else {
			src = &thread_infos[thread_nr];
			thread_nr++;
		}

		crc = ~0;
		if (datachk((uint8_t *)siginf_body(info), _si_fields_sz, &crc)) {
			fail("CRC mismatch");
			return;
		}

		if (memcmp(info, src, siginfo_filled)) {
			fail("Source and received info are differ");
			return;
		}

		numsig++;
		return;
	}

	pr_perror("Unexpected signal");
	exit(1);
}

static int thread_id;

static void *thread_fn(void *args)
{
	sigset_t blockmask, oldset, newset;
	struct sigaction act;

	memset(&oldset, 0, sizeof(oldset));
	memset(&newset, 0, sizeof(oldset));

	sigfillset(&blockmask);
	sigdelset(&blockmask, SIGTERM);

	if (sigprocmask(SIG_BLOCK, &blockmask, NULL) == -1) {
		pr_perror("sigprocmask");
		return NULL;
	}

	if (sigprocmask(SIG_SETMASK, NULL, &oldset) == -1) {
		pr_perror("sigprocmask");
		return NULL;
	}

	thread_id = syscall(SYS_gettid);

	act.sa_flags = SA_SIGINFO | SA_RESTART;
	act.sa_sigaction = sig_handler;
	sigemptyset(&act.sa_mask);

	sigaddset(&act.sa_mask, TESTSIG);
	sigaddset(&act.sa_mask, THREADSIG);
	if (sigaction(TESTSIG, &act, NULL)) {
		pr_perror("sigaction() failed");
		return NULL;
	}

	pthread_mutex_unlock(&init_lock);
	pthread_mutex_lock(&exit_lock);

	if (sigprocmask(SIG_UNBLOCK, &blockmask, &newset) == -1) {
		pr_perror("sigprocmask");
		return NULL;
	}

	sigdelset(&oldset, SIGTRAP);
	sigdelset(&newset, SIGTRAP);
	if (memcmp(&newset, &oldset, sizeof(newset))) {
		fail("The signal blocking mask was changed");
		numsig = INT_MAX;
	}

	return NULL;
}

static int sent_sigs;

int send_siginfo(int signo, pid_t pid, pid_t tid, int group, siginfo_t *info)
{
	static int si_code = -10;
	uint32_t crc = ~0;

	info->si_code = si_code;
	si_code--;
	info->si_signo = signo;
	datagen((uint8_t *)siginf_body(info), _si_fields_sz, &crc);

	sent_sigs++;

	if (group)
		return syscall(SYS_rt_sigqueueinfo, pid, signo, info);
	else
		return syscall(SYS_rt_tgsigqueueinfo, pid, tid, signo, info);
}

int main(int argc, char **argv)
{
	sigset_t blockmask, oldset, newset;
	struct sigaction act;
	pthread_t pthrd;
	siginfo_t infop;
	int i;

	memset(&oldset, 0, sizeof(oldset));
	memset(&newset, 0, sizeof(oldset));

	test_init(argc, argv);
	pthread_mutex_init(&exit_lock, NULL);
	pthread_mutex_lock(&exit_lock);
	pthread_mutex_init(&init_lock, NULL);
	pthread_mutex_lock(&init_lock);

	if (pthread_create(&pthrd, NULL, thread_fn, NULL)) {
		pr_perror("Can't create a thread");
		return 1;
	}

	pthread_mutex_lock(&init_lock);

	sigfillset(&blockmask);
	sigdelset(&blockmask, SIGTERM);

	if (sigprocmask(SIG_BLOCK, &blockmask, NULL) == -1) {
		pr_perror("sigprocmask");
		return -1;
	}

	if (sigprocmask(SIG_BLOCK, NULL, &oldset) == -1) {
		pr_perror("sigprocmask");
		return -1;
	}

	child = fork();
	if (child == -1) {
		pr_perror("fork");
		return -1;
	}

	if (child == 0)
		return 5; /* SIGCHLD */
	if (waitid(P_PID, child, &infop, WNOWAIT | WEXITED)) {
		pr_perror("waitid");
		return 1;
	}

	sent_sigs++;

	for (i = 0; i < sizeof(share_infos) / sizeof(siginfo_t); i++) {
		send_siginfo(TESTSIG, getpid(), -1, 1, share_infos + i);
	}

	for (i = 0; i < sizeof(self_infos) / sizeof(siginfo_t); i++) {
		send_siginfo(THREADSIG, getpid(), getpid(), 0, self_infos + i);
	}

	for (i = 0; i < sizeof(thread_infos) / sizeof(siginfo_t); i++) {
		send_siginfo(THREADSIG, getpid(), thread_id, 0, thread_infos + i);
	}

	act.sa_flags = SA_SIGINFO | SA_RESTART;
	act.sa_sigaction = sig_handler;
	sigemptyset(&act.sa_mask);

	if (sigaction(SIGCHLD, &act, NULL)) {
		pr_perror("sigaction() failed");
		return -1;
	}

	sigaddset(&act.sa_mask, TESTSIG);
	sigaddset(&act.sa_mask, THREADSIG);
	if (sigaction(TESTSIG, &act, NULL)) {
		pr_perror("sigaction() failed");
		return -1;
	}

	if (sigaction(THREADSIG, &act, NULL)) {
		pr_perror("sigaction() failed");
		return -1;
	}

	test_daemon();

	test_waitsig();

	if (sigprocmask(SIG_UNBLOCK, &blockmask, &newset) == -1) {
		pr_perror("sigprocmask");
		return -1;
	}
	pthread_mutex_unlock(&exit_lock);
	pthread_join(pthrd, NULL);

	sigdelset(&oldset, SIGTRAP);
	sigdelset(&newset, SIGTRAP);
	if (memcmp(&newset, &oldset, sizeof(newset))) {
		fail("The signal blocking mask was changed");
		return 1;
	}

	if (numsig == sent_sigs)
		pass();

	return 0;
}
