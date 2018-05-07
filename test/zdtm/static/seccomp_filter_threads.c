#include <unistd.h>
#include <stdbool.h>
#include <signal.h>
#include <stddef.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/syscall.h>

#ifdef __NR_seccomp
# include <linux/seccomp.h>
# include <linux/filter.h>
# include <linux/limits.h>
# include <pthread.h>
#endif

#include "zdtmtst.h"

#ifndef SECCOMP_SET_MODE_FILTER
#define SECCOMP_SET_MODE_FILTER 1
#endif

#ifndef SECCOMP_FILTER_FLAG_TSYNC
#define SECCOMP_FILTER_FLAG_TSYNC 1
#endif

const char *test_doc	= "Check threads to carry different seccomps";
const char *test_author	= "Cyrill Gorcunov <gorcunov@openvz.org>";

#ifdef __NR_seccomp

static task_waiter_t tw;

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

void *thread_main(void *arg)
{
	if (filter_syscall(__NR_ptrace, 0) < 0)
		pthread_exit((void *)1);

	test_msg("__NR_ptrace filtered inside a sole thread\n");

	task_waiter_complete(&tw, 1);
	task_waiter_wait4(&tw, 2);

	ptrace(PTRACE_TRACEME);
	pthread_exit((void *)1);
}

int main(int argc, char ** argv)
{
	int ret, mode, status;
	pid_t pid;

	test_init(argc, argv);
	task_waiter_init(&tw);

	pid = fork();
	if (pid < 0) {
		pr_perror("fork");
		return -1;
	}

	if (pid == 0) {
		pthread_t thread;
		void *p = NULL;

		zdtm_seccomp = 1;

		pthread_create(&thread, NULL, thread_main, NULL);
		if (pthread_join(thread, &p) != 0) {
			pr_perror("pthread_join");
			exit(1);
		}

		syscall(__NR_exit, p);
	}

	task_waiter_wait4(&tw, 1);

	test_daemon();
	test_waitsig();

	task_waiter_complete(&tw, 2);
	mode = get_seccomp_mode(pid);

	if (mode != SECCOMP_MODE_DISABLED) {
		fail("seccomp mode mismatch %d\n", mode);
		return 1;
	}

	ret = waitpid(pid, &status, 0);
	if (ret != pid) {
		fail("waitpid: %d != %d", ret, pid);
		exit(1);
	}

	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
		fail("expected 0 exit, got %d\n", WEXITSTATUS(status));
		exit(1);
	}

	pass();
	return 0;
}

#else /* __NR_seccomp */

#define TEST_SKIP_REASON "incompatible kernel (no seccomp)"
#include "skip-me.c"

#endif /* __NR_seccomp */
