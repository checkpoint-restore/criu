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
#endif

#include "zdtmtst.h"

const char *test_doc	= "Check that SECCOMP_MODE_FILTER is restored";
const char *test_author	= "Tycho Andersen <tycho.andersen@canonical.com>";

#ifdef __NR_seccomp

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

int filter_syscall(int syscall_nr)
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

	if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &bpf_prog) < 0) {
		pr_perror("prctl failed");
		return -1;
	}

	return 0;
}

int main(int argc, char ** argv)
{
	pid_t pid;
	int mode, status;
	int sk_pair[2], sk, ret;
	char c = 'K';

	test_init(argc, argv);

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

		pid_t pid2;

		sk = sk_pair[1];
		close(sk_pair[0]);

		if (filter_syscall(__NR_ptrace) < 0)
			_exit(1);

		if (filter_syscall(__NR_fstat) < 0)
			_exit(1);

		zdtm_seccomp = 1;
		test_msg("SECCOMP_MODE_FILTER is enabled\n");

		pid2 = fork();
		if (pid2 < 0)
			_exit(1);

		if (!pid2) {

			if (write(sk, &c, 1) != 1) {
				pr_perror("write");
				_exit(1);
			}

			if (read(sk, &c, 1) != 1) {
				pr_perror("read");
				_exit(1);
			}

			/* We expect to be killed by our policy above. */
			ptrace(PTRACE_TRACEME);
			_exit(1);
		}

		if (waitpid(pid2, &status, 0) != pid2) {
			pr_perror("waitpid");
			_exit(1);
		}

		if (WTERMSIG(status) != SIGSYS) {
			pr_perror("expected SIGSYS, got %d\n", WTERMSIG(status));
			_exit(1);
		}

		_exit(0);
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

	if (mode != SECCOMP_MODE_FILTER) {
		fail("seccomp mode mismatch %d\n", mode);
		return 1;
	}

	if (waitpid(pid, &status, 0) != pid) {
		pr_perror("waitpid");
		_exit(1);
	}

	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
		fail("bad exit status");
		return 1;
	}

	pass();

	return 0;
err:
	kill(pid, SIGKILL);
	return 1;
}


#else /* __NR_seccomp */

#include "skip-me.c"

#endif /* __NR_seccomp */
