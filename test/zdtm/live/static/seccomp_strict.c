#include <unistd.h>
#include <stdbool.h>
#include <signal.h>
#include <sys/prctl.h>
#include <linux/seccomp.h>
#include <linux/limits.h>
#include "zdtmtst.h"

const char *test_doc	= "Check that SECCOMP_MODE_STRICT is restored";
const char *test_author	= "Tycho Andersen <tycho.andersen@canonical.com>";

int get_seccomp_mode(pid_t pid, bool after_checkpoint)
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
		char state;

		if (after_checkpoint && sscanf(buf, "State: %c %*s", &state) == 1 && state != 'R') {
			fail("resumed but state is not R (%c), seccomp killed the process during resume\n", state);
			break;
		}

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
	int ret = 1, mode;

	test_init(argc, argv);

	pid = fork();
	if (pid < 0) {
		err("fork");
		return -1;
	}

	if (pid == 0) {
		if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_STRICT) < 0) {
			err("prctl failed");
			return -1;
		}

		while(1)
			/* can't sleep() here, seccomp kills us */;
	}

	while(get_seccomp_mode(pid, false) != SECCOMP_MODE_STRICT)
		sleep(1);

	test_daemon();
	test_waitsig();

	mode = get_seccomp_mode(pid, true);
	if (mode != SECCOMP_MODE_STRICT) {
		fail("seccomp mode mismatch %d\n", mode);
	} else {
		pass();
		ret = 0;
	}

	kill(pid, SIGKILL);
	return ret;
}
