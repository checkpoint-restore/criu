#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <unistd.h>
#include <syscall.h>
#include <sys/wait.h>

#include "zdtmtst.h"

const char *test_doc = "Check, that stopped tasts are restored correctly";
const char *test_author = "Andrew Vagin <avagin@parallels.com>";

int main(int argc, char **argv)
{
	pid_t pid;
	siginfo_t infop;
	int p[2], ret, status;

	test_init(argc, argv);

	if (pipe(p)) {
		pr_perror("Unable to create pipe");
		return 1;
	}

	pid = test_fork();
	if (pid < 0)
		return -1;
	else if (pid == 0) {
		char c;

		close(p[1]);
		ret = read(p[0], &c, 1);
		if (ret != 1) {
			pr_perror("Unable to read: %d", ret);
			return 1;
		}

		return 0;
	}
	close(p[0]);

	kill(pid, SIGSTOP);
	if (waitid(P_PID, pid, &infop, WNOWAIT | WSTOPPED) < 0) {
		pr_perror("waitid");
		return 1;
	}
#ifdef ZDTM_STOPPED_TKILL
	syscall(__NR_tkill, pid, SIGSTOP);
#endif
#ifdef ZDTM_STOPPED_KILL
	kill(pid, SIGSTOP);
#endif

	write(p[1], "0", 1);
	close(p[1]);

	test_daemon();
	test_waitsig();

	// Return immediately if child run or stopped(by SIGSTOP)
	if (waitpid(pid, &status, WUNTRACED | WCONTINUED) == -1) {
		pr_perror("Unable to wait child");
		goto out;
	}

	if (WIFSTOPPED(status))
		test_msg("The procces stopped\n");
	else {
		fail("The process doesn't stopped");
		goto out;
	}

	kill(pid, SIGCONT);

	if (waitpid(pid, &status, 0) == -1) {
		pr_perror("Unable to wait child");
		goto out;
	}

	if (WIFEXITED(status))
		pass();
	else
		fail("The process doesn't continue");
out:
	return 0;
}
