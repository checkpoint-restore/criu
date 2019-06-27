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
#include <sys/mman.h>

#ifdef __NR_seccomp
# include <linux/seccomp.h>
# include <linux/filter.h>
# include <linux/limits.h>
# include <pthread.h>
#endif

#include "zdtmtst.h"
#include "lock.h"

#ifndef SECCOMP_SET_MODE_FILTER
#define SECCOMP_SET_MODE_FILTER 1
#endif

#ifndef SECCOMP_FILTER_FLAG_TSYNC
#define SECCOMP_FILTER_FLAG_TSYNC 1
#endif

const char *test_doc	= "Check threads to carry different seccomps";
const char *test_author	= "Cyrill Gorcunov <gorcunov@openvz.org>";

#ifdef __NR_seccomp

static long sys_gettid(void) { return syscall(__NR_gettid); }

static futex_t *wait_rdy;
static futex_t *wait_run;

static int magic = 1234;

int get_seccomp_mode(pid_t pid)
{
	FILE *f;
	char buf[PATH_MAX];

	sprintf(buf, "/proc/%d/status", pid);
	f = fopen(buf, "r");
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
		BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ERRNO | (SECCOMP_RET_DATA & magic)),
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

int tigger_ptrace(void) { return ptrace(PTRACE_TRACEME); }
int trigger_prctl(void) { return prctl(PR_SET_PDEATHSIG, 9, 0, 0, 0); }
int trigger_mincore(void) { return mincore(NULL, 0, NULL); }

#define gen_param(__syscall_nr, __trigger)		\
{							\
	.syscall_name	= # __syscall_nr,		\
	.syscall_nr	= __syscall_nr,			\
	.trigger	= __trigger,			\
}

struct {
	char		*syscall_name;
	unsigned int	syscall_nr;
	int		(*trigger)(void);
} pthread_seccomp_params[] = {
	gen_param(__NR_ptrace, tigger_ptrace),
	gen_param(__NR_prctl, trigger_prctl),
	gen_param(__NR_mincore, trigger_mincore),
};

#define WAITER_VALS_OFFSET (ARRAY_SIZE(pthread_seccomp_params) * 2)

void *thread_main(void *arg)
{
	int ret;
	size_t nr = (long) arg;

	if (filter_syscall(pthread_seccomp_params[nr].syscall_nr, 0) < 0)
		pthread_exit((void *)1);

	test_msg("%s filtered inside a sole thread %lu\n",
		 pthread_seccomp_params[nr].syscall_name,
		 sys_gettid());

	futex_inc_and_wake(wait_rdy);
	futex_wait_while_lt(wait_run, 1);

	test_msg("Triggering %zu %s thread %lu\n",
		 nr, pthread_seccomp_params[nr].syscall_name,
		 sys_gettid());

	ret = pthread_seccomp_params[nr].trigger();
	if (ret == -1 && errno == magic)
		return (void *)0;

	test_msg("Abnormal exit %zu thread %lu\n", nr, sys_gettid());
	return (void *)1;
}

int main(int argc, char ** argv)
{
	int ret, mode, status;
	size_t i;
	pid_t pid;

	test_init(argc, argv);

	wait_rdy = mmap(NULL, sizeof(*wait_rdy), PROT_READ | PROT_WRITE,
			MAP_ANONYMOUS | MAP_SHARED, -1, 0);
	wait_run = mmap(NULL, sizeof(*wait_rdy), PROT_READ | PROT_WRITE,
			MAP_ANONYMOUS | MAP_SHARED, -1, 0);

	if (wait_rdy == MAP_FAILED || wait_run == MAP_FAILED) {
		pr_perror("mmap failed\n");
		exit(1);
	}

	futex_init(wait_rdy);
	futex_init(wait_run);

	futex_set(wait_rdy, 0);
	futex_set(wait_run, 0);

	pid = fork();
	if (pid < 0) {
		pr_perror("fork");
		return -1;
	}


	if (pid == 0) {
		pthread_t thread[ARRAY_SIZE(pthread_seccomp_params)];
		void *ret;

		zdtm_seccomp = 1;

		for (i = 0; i < ARRAY_SIZE(pthread_seccomp_params); i++) {
			if (pthread_create(&thread[i], NULL, thread_main, (void *)i)) {
				pr_perror("pthread_create");
				exit(1);
			}
		}

		for (i = 0; i < ARRAY_SIZE(pthread_seccomp_params); i++) {
			test_msg("Waiting thread %zu\n", i);
			if (pthread_join(thread[i], &ret) != 0) {
				pr_perror("pthread_join");
				exit(1);
			}

			if (ret != 0)
				syscall(__NR_exit, 1);
		}

		syscall(__NR_exit, 0);
	}

	futex_wait_until(wait_rdy, ARRAY_SIZE(pthread_seccomp_params));

	test_daemon();
	test_waitsig();

	futex_inc_and_wake(wait_run);
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
