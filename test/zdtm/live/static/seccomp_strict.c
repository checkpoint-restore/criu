#include <unistd.h>
#include <stdbool.h>
#include <signal.h>
#include <sys/prctl.h>
#include <linux/seccomp.h>
#include <linux/limits.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include "zdtmtst.h"

const char *test_doc	= "Check that SECCOMP_MODE_STRICT is restored";
const char *test_author	= "Tycho Andersen <tycho.andersen@canonical.com>";

int get_seccomp_mode(pid_t pid)
{
	FILE *f;
	char buf[PATH_MAX];

	sprintf(buf, "/proc/%d/status", pid);
	f = fopen(buf, "r+");
	if (!f) {
		err("fopen failed");
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

int main(int argc, char ** argv)
{
	pid_t pid;
	int mode, status;
	int sk_pair[2], sk;
	char c = 'K';

	test_init(argc, argv);

	if (socketpair(PF_LOCAL, SOCK_SEQPACKET, 0, sk_pair)) {
		err("socketpair");
		return -1;
	}

	pid = fork();
	if (pid < 0) {
		err("fork");
		return -1;
	}

	if (pid == 0) {
		sk = sk_pair[1];
		close(sk_pair[0]);
		zdtm_seccomp = 1;

		if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_STRICT) < 0) {
			err("prctl failed");
			return -1;
		}
		test_msg("SECCOMP_MODE_STRICT is enabled\n");

		if (write(sk, &c, 1) != 1) {
			err("write");
			return -1;
		}
		if (read(sk, &c, 1) != 1) {
			_exit(1);
			err("read");
			return -1;
		}

		syscall(__NR_exit, 0);
	}

	sk = sk_pair[0];
	close(sk_pair[1]);

	if (read(sk, &c, 1) != 1) {
		err("read");
		goto err;
	}

	test_daemon();
	test_waitsig();

	mode = get_seccomp_mode(pid);
	if (write(sk, &c, 1) != 1) {
		err("write");
		goto err;
	}
	if (waitpid(pid, &status, 0) != pid) {
		err("waitpid");
		exit(1);
	}
	if (status != 0) {
		err("The child exited with an unexpected code %d", status);
		exit(1);
	}
	if (mode != SECCOMP_MODE_STRICT) {
		fail("seccomp mode mismatch %d\n", mode);
		return 1;
	}

	pass();

	return 0;
err:
	kill(pid, SIGKILL);
	return 1;
}
