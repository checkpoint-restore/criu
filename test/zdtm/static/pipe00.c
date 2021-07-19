#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <sys/wait.h>

#include "zdtmtst.h"

const char *test_doc = "Lock inversion";
const char *test_author = "Andrey Vagin <avagin@parallels.com>";

#define TEST_STRING "Hello world"

int main(int argc, char **argv)
{
	int pipe1[2];
	int pipe2[2];
	int ret;
	pid_t pid;
	char buf[sizeof(TEST_STRING)];
	task_waiter_t t;

	test_init(argc, argv);

	task_waiter_init(&t);

	ret = pipe(pipe1);
	if (ret)
		return 1;

	ret = pipe(pipe2);
	if (ret)
		return 1;

	pid = test_fork();
	if (pid < 0) {
		pr_perror("Can't fork");
		exit(1);
	} else if (pid == 0) {
		if (dup2(pipe1[1], 11) == -1 || dup2(pipe2[0], 12) == -1) {
			pr_perror("dup2 failed");
			return 1;
		}
	} else {
		if (dup2(pipe1[0], 12) == -1 || dup2(pipe2[1], 11) == -1) {
			pr_perror("dup2 failed");
			goto err;
		}
	}

	close(pipe2[0]);
	close(pipe2[1]);
	close(pipe1[0]);
	close(pipe1[1]);

	if (pid > 0) {
		int status;

		task_waiter_wait4(&t, 1);

		test_daemon();

		test_waitsig();

		ret = read(12, buf, sizeof(TEST_STRING));
		if (ret != sizeof(TEST_STRING)) {
			pr_perror("read failed: %d", ret);
			goto err;
		}
		ret = write(11, TEST_STRING, sizeof(TEST_STRING));
		if (ret != sizeof(TEST_STRING)) {
			pr_perror("write failed: %d", ret);
			goto err;
		}
		close(11);
		ret = read(12, buf, sizeof(TEST_STRING));
		if (ret != sizeof(TEST_STRING)) {
			pr_perror("read failed: %d", ret);
			goto err;
		}
		if (strcmp(TEST_STRING, buf)) {
			pr_perror("data curruption");
			goto err;
		}

		ret = wait(&status);
		if (ret == -1 || !WIFEXITED(status) || WEXITSTATUS(status)) {
			kill(pid, SIGKILL);
			goto err;
		}

		pass();
	} else {
		task_waiter_complete(&t, 1);
		ret = write(11, TEST_STRING, sizeof(TEST_STRING));
		if (ret != sizeof(TEST_STRING)) {
			pr_perror("write failed: %d", ret);
			return 1;
		}
		ret = read(12, buf, sizeof(TEST_STRING));
		if (ret != sizeof(TEST_STRING)) {
			pr_perror("read failed: %d", ret);
			return 1;
		}
		ret = write(11, TEST_STRING, sizeof(TEST_STRING));
		if (ret != sizeof(TEST_STRING)) {
			pr_perror("write failed: %d", ret);
			return 1;
		}
		close(11);
		if (strcmp(TEST_STRING, buf)) {
			pr_perror("data curruption");
			return 1;
		}
	}

	return 0;
err:
	pr_perror("FAIL");
	return 1;
}
