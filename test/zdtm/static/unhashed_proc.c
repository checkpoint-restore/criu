#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <string.h>
#include <linux/limits.h>

#include "zdtmtst.h"

const char *test_doc = "Chdir into unhashed proc entry";
const char *test_author = "Konstantin Khlebnikov <khlebnikov@openvz.org>";

int main(int argc, char **argv)
{
	int pid, len;
	char cwd1[PATH_MAX], cwd2[PATH_MAX];

	test_init(argc, argv);

	pid = fork();
	if (pid < 0) {
		pr_perror("fork failed");
		exit(1);
	} else if (!pid) {
		pause();
		return 0;
	}

	sprintf(cwd1, "/proc/%d", pid);

	if (chdir(cwd1) < 0) {
		kill(pid, SIGKILL);
		pr_perror("chdir failed");
		exit(1);
	}

	kill(pid, SIGKILL);
	waitpid(pid, NULL, 0);

	if (getcwd(cwd1, sizeof(cwd1))) {
		pr_perror("successful getcwd: %s", cwd1);
		exit(1);
	} else if (errno != ENOENT) {
		pr_perror("wrong errno");
		exit(1);
	}

	len = readlink("/proc/self/cwd", cwd1, sizeof(cwd1));
	if (len < 0) {
		pr_perror("can't read cwd symlink");
		exit(1);
	}
	cwd1[len] = 0;

	test_daemon();
	test_waitsig();

	if (getcwd(cwd2, sizeof(cwd2))) {
		fail("successful getcwd: %s", cwd2);
		exit(1);
	} else if (errno != ENOENT) {
		fail("wrong errno");
		exit(1);
	}

	len = readlink("/proc/self/cwd", cwd2, sizeof(cwd2) - 1);
	if (len < 0) {
		fail("can't read cwd symlink");
		exit(1);
	}
	cwd2[len] = 0;

	if (strcmp(cwd1, cwd2))
		test_msg("cwd differs: %s != %s\n", cwd1, cwd2);

	pass();

	return 0;
}
