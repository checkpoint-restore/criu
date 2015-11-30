#include <unistd.h>
#include <stdbool.h>
#include <signal.h>
#include <stddef.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/limits.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <pthread.h>
#include "zdtmtst.h"

#undef __NR_seccomp

#ifdef __NR_seccomp
#define HAVE_SECCOMP 1
#else
#define HAVE_SECCOMP 0
#define __NR_seccomp -1
#endif

#ifndef SECCOMP_SET_MODE_FILTER
#define SECCOMP_SET_MODE_FILTER 1
#endif

#ifndef SECCOMP_FILTER_FLAG_TSYNC
#define SECCOMP_FILTER_FLAG_TSYNC 1
#endif

const char *test_doc	= "Check that SECCOMP_FILTER_FLAG_TSYNC works correctly after restore";
const char *test_author	= "Tycho Andersen <tycho.andersen@canonical.com>";

pthread_mutex_t getpid_wait;

int get_seccomp_mode(pid_t pid)
{
	FILE *f;
	char buf[PATH_MAX];

	sprintf(buf, "/proc/%d/status", pid);
	f = fopen(buf, "r+");
	if (!f) {
		pr_perror("fopen failed");
		return -1;
	}

	while (NULL != fgets(buf, sizeof(buf), f)) {
		int mode;

		if (sscanf(buf, "Seccomp:\t%d", &mode) != 1)
			continue;

		fclose(f);
		return mode;
	}
	fclose(f);

	return -1;
}

int filter_syscall(int syscall_nr, unsigned int flags)
{
	struct sock_filter filter[] = {
		BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offsetof(struct seccomp_data, nr)),
		BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, syscall_nr, 0, 1),
		BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL),
		BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW),
	};

	struct sock_fprog bpf_prog = {
		.len = (unsigned short)(sizeof(filter)/sizeof(filter[0])),
		.filter = filter,
	};

	if (syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER, flags, &bpf_prog) < 0) {
		pr_perror("seccomp failed");
		return -1;
	}

	return 0;
}

void *wait_and_getpid(void *arg)
{
	pthread_mutex_lock(&getpid_wait);
	pthread_mutex_unlock(&getpid_wait);
	pthread_mutex_destroy(&getpid_wait);

	/* we expect the tg to get killed by the seccomp filter that was
	 * installed via TSYNC */
	ptrace(PTRACE_TRACEME);
	pthread_exit((void *)1);
}

int main(int argc, char ** argv)
{
	pid_t pid;
	int mode, status;
	int sk_pair[2], sk, ret;
	char c = 'K';

	test_init(argc, argv);

	if (!HAVE_SECCOMP) {
		skip("no seccomp present in this kernel\n");
		return 0;
	}

	if (socketpair(PF_LOCAL, SOCK_SEQPACKET, 0, sk_pair)) {
		pr_perror("socketpair");
		return -1;
	}

	pid = fork();
	if (pid < 0) {
		pr_perror("fork");
		return -1;
	}

	if (pid == 0) {
		pthread_t th;
		void *p = NULL;

		if (pthread_mutex_init(&getpid_wait, NULL)) {
			pr_perror("pthread_mutex_init");
			_exit(1);
		}

		sk = sk_pair[1];
		close(sk_pair[0]);

		if (filter_syscall(__NR_getpid, 0) < 0)
			_exit(1);

		zdtm_seccomp = 1;

		pthread_mutex_lock(&getpid_wait);
		pthread_create(&th, NULL, wait_and_getpid, NULL);

		test_msg("SECCOMP_MODE_FILTER is enabled\n");

		if (write(sk, &c, 1) != 1) {
			pr_perror("write");
			_exit(1);
		}

		if (read(sk, &c, 1) != 1) {
			pr_perror("read");
			_exit(1);
		}

		/* Now we have c/r'd with a shared filter, so let's install
		 * another filter with TSYNC and make sure that it is
		 * inherited.
		 */
		if (filter_syscall(__NR_ptrace, SECCOMP_FILTER_FLAG_TSYNC) < 0)
			_exit(1);

		pthread_mutex_unlock(&getpid_wait);
		if (pthread_join(th, &p) != 0) {
			pr_perror("pthread_join");
			exit(1);
		}

		/* Here we're abusing pthread exit slightly: if the thread gets
		 * to call pthread_exit, the value of p is one, but if it gets
		 * killed pthread_join doesn't set a value since the thread
		 * didn't, so the value is null; we exit 0 to indicate success
		 * as usual.
		 */
		syscall(__NR_exit, p);
	}

	sk = sk_pair[0];
	close(sk_pair[1]);

	if ((ret = read(sk, &c, 1)) != 1) {
		pr_perror("read %d", ret);
		goto err;
	}

	test_daemon();
	test_waitsig();

	mode = get_seccomp_mode(pid);
	if (write(sk, &c, 1) != 1) {
		pr_perror("write");
		goto err;
	}
	if (waitpid(pid, &status, 0) != pid) {
		pr_perror("waitpid");
		exit(1);
	}

	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
		pr_perror("expected 0 exit, got %d\n", WEXITSTATUS(status));
		exit(1);
	}

	if (mode != SECCOMP_MODE_FILTER) {
		fail("seccomp mode mismatch %d\n", mode);
		return 1;
	}

	pass();

	return 0;
err:
	kill(pid, SIGKILL);
	return 1;
}
