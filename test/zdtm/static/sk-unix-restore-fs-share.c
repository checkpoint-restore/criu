#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "zdtmtst.h"

const char *test_doc = "Test non-empty process group with terminated parent and unix socket";
const char *test_author = "Qiao Ma <mqaio@linux.alibaba.com>";

char *filename;
TEST_OPTION(filename, string, "socket file name", 1);

static int create_and_connect(void)
{
	struct sockaddr_un addr;
	int client_fd;

	client_fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (client_fd == -1) {
		pr_perror("socket");
		return -1;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	if (snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", filename) >= (int)sizeof(addr.sun_path)) {
		pr_err("Socket path too long\n");
		close(client_fd);
		return -1;
	}

	if (connect(client_fd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
		pr_perror("connect");
		close(client_fd);
		return -1;
	}

	return 0;
}

static int child(int ready_fd)
{
	int listen_fd;
	struct sockaddr_un addr;
	int ret = EXIT_FAILURE;

	listen_fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (listen_fd == -1) {
		pr_perror("socket");
		return EXIT_FAILURE;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	if (strlen(filename) >= sizeof(addr.sun_path)) {
		pr_err("Socket path too long\n");
		goto cleanup;
	}
	strncpy(addr.sun_path, filename, sizeof(addr.sun_path));

	unlink(filename); /* Ignore error if file doesn't exist */

	if (bind(listen_fd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
		pr_perror("bind");
		goto cleanup;
	}

	if (listen(listen_fd, 5) == -1) {
		pr_perror("listen");
		goto cleanup;
	}

	if (create_and_connect() != 0) {
		pr_err("Failed to create and connect\n");
		goto cleanup;
	}

	/* Signal parent that socket is ready */
	if (write(ready_fd, "1", 1) != 1) {
		pr_perror("write ready_fd");
		goto cleanup;
	}

	/* Wait indefinitely */
	pause();

	ret = EXIT_SUCCESS;
cleanup:
	if (listen_fd != -1)
		close(listen_fd);
	unlink(filename);

	return ret;
}

static int zombie_leader(int *cpid)
{
	char buf;
	pid_t pid;
	int pipefd[2];

	if (pipe(pipefd) == -1) {
		pr_perror("pipe");
		return EXIT_FAILURE;
	}

	if (setpgid(0, 0) == -1) {
		pr_perror("setpgid");
		return EXIT_FAILURE;
	}

	pid = fork();
	if (pid < 0) {
		pr_perror("Failed to fork child");
		return EXIT_FAILURE;
	}

	if (pid == 0) {
		/* Close read end */
		close(pipefd[0]);
		exit(child(pipefd[1]));
	}

	/* Close write end in parent */
	close(pipefd[1]);

	/* Wait for child to set up socket */
	if (read(pipefd[0], &buf, 1) != 1) {
		pr_err("Failed to receive readiness signal from child\n");
		close(pipefd[0]);
		return EXIT_FAILURE;
	}
	close(pipefd[0]);

	*cpid = pid;
	return EXIT_SUCCESS;
}

int main(int argc, char **argv)
{
	int ret = EXIT_FAILURE, status;
	pid_t pid;
	int *cpid;

	test_init(argc, argv);

	cpid = mmap(NULL, sizeof(int), PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_SHARED, -1, 0);
	if (cpid == MAP_FAILED) {
		pr_perror("mmap");
		return EXIT_FAILURE;
	}
	*cpid = 0;

	pid = fork();
	if (pid < 0) {
		pr_perror("Failed to fork zombie");
		goto out;
	}

	if (pid == 0)
		exit(zombie_leader(cpid));

	if (waitpid(pid, &status, 0) < 0) {
		pr_perror("Failed to waitpid zombie");
		goto out;
	}

	if (!WIFEXITED(status) || WEXITSTATUS(status) != EXIT_SUCCESS) {
		pr_err("Unexpected exit code: %d\n", WEXITSTATUS(status));
		goto out;
	}

	if (!*cpid) {
		pr_err("Don't know grandchild's pid\n");
		goto out;
	}

	test_daemon();
	test_waitsig();

	ret = EXIT_SUCCESS;
	pass();
out:
	/* Clean up */
	if (*cpid)
		kill(*cpid, SIGKILL);

	munmap(cpid, sizeof(int));

	return ret;
}
