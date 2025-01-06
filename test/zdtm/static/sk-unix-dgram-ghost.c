#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdbool.h>
#include <limits.h>
#include <errno.h>
#include <dirent.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>

#include "zdtmtst.h"

const char *test_doc = "Check data of bound ghost DGRAM unix socket and possibility to connect";
const char *test_author = "Alexander Mikhalitsyn <alexander@mihalicyn.com>";

/*
 * PROCESS_NUM | FREEZE_FREQ
 * 3           | 1 / 5
 * 4           | 1 / 5
 * 5           | 2 / 5
 * 10          | 10 / 10
 */
#define PROCESSES_NUM 10

#define MSG "hello"
char filename[PATH_MAX];
char *dirname;
TEST_OPTION(dirname, string, "directory name", 1);

static int fill_sock_name(struct sockaddr_un *name, const char *filename)
{
	char *cwd;

	cwd = get_current_dir_name();
	if (strlen(filename) + strlen(cwd) + 1 >= sizeof(name->sun_path)) {
		pr_err("Name %s/%s is too long for socket\n", cwd, filename);
		return -1;
	}

	name->sun_family = AF_LOCAL;
	ssprintf(name->sun_path, "%s/%s", cwd, filename);
	return 0;
}

static int client(int i, task_waiter_t t)
{
	struct sockaddr_un addr;
	int sk;

	sk = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (sk < 0) {
		pr_perror("open client %d", i);
		return 1;
	}

	if (fill_sock_name(&addr, filename) < 0) {
		pr_err("%s is too long for socket\n", filename);
		return 1;
	}

	if (connect(sk, (struct sockaddr *)&addr, sizeof(struct sockaddr_un)) < 0) {
		pr_perror("connect failed %d", i);
		return 1;
	}

	/* we are ready to c/r */
	task_waiter_complete(&t, 1);

	/* wait for server let us to send data */
	task_waiter_wait4(&t, 2);

	test_msg("child %d: lets send\n", i);

	if (send(sk, MSG, sizeof(MSG), 0) != sizeof(MSG)) {
		pr_perror("send failed %d", i);
		return 1;
	}

	test_msg("child %d: MSG was sent\n", i);

	/* notify server that we sent data */
	task_waiter_complete(&t, 3);

	return 0;
}

static void child_exited(int signo)
{
	int status;
	pid_t pid;

	while (1) {
		pid = waitpid(-1, &status, WNOHANG);
		if (pid == -1) {
			if (errno == ECHILD)
				break;

			fail("wait failed");
			exit(1);
		}

		if (pid == 0)
			return;

		if (status) {
			pr_err("A child (pid: %d) exited with 0x%x\n", pid, status);
			exit(1);
		}
	}
}

int main(int argc, char **argv)
{
	struct sockaddr_un addr;
	int srv, ret;
	size_t i;
	char buf[1024];
	task_waiter_t t[PROCESSES_NUM];

	test_init(argc, argv);

	ssprintf(filename, "%s/%s", dirname, "sk");

	if (fill_sock_name(&addr, filename) < 0) {
		pr_err("%s is too long for socket\n", filename);
		ret = 1;
		goto clean;
	}

	if (signal(SIGCHLD, child_exited) == SIG_ERR) {
		pr_perror("can't set SIGCHLD handler");
		exit(1);
	}

	for (i = 0; i < PROCESSES_NUM; i++)
		task_waiter_init(&t[i]);

	if (mkdir(dirname, 0755) < 0) {
		if (errno != EEXIST) {
			pr_perror("Can't create %s", dirname);
			return 1;
		}
	}

	/*
	 * Freeze happens if unix socket is the *last* file descriptor.
	 * So, if we for example, move task_waiter_init() after server
	 * socket creation we loose reproduce.
	 */
	srv = socket(AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK, 0);
	if (srv < 0) {
		pr_perror("open srv");
		ret = 1;
		goto clean;
	}

	if (bind(srv, (struct sockaddr *)&addr, sizeof(struct sockaddr_un))) {
		pr_perror("bind srv");
		ret = 1;
		goto clean;
	}

	for (i = 0; i < PROCESSES_NUM; i++) {
		ret = test_fork();
		if (ret == -1) {
			pr_perror("fork");
			ret = 1;
			goto clean;
		}

		if (ret == 0) {
			close(srv);
			exit(client(i, t[i]));
		}

		task_waiter_wait4(&t[i], 1);
	}

	/*
	 * It's very important part of this test-case to make
	 * *ghost* unix socket. Because problem with criu freeze
	 * appears especially with *ghost* unix socket.
	 */
	unlink(addr.sun_path);

	ret = 1;

	test_daemon();
	test_waitsig();

	test_msg("C/R complete\n");

	/* Let children send data to server socket. */
	for (i = 0; i < PROCESSES_NUM; i++)
		task_waiter_complete(&t[i], 2);

	/* Wait for children to send data. */
	for (i = 0; i < PROCESSES_NUM; i++)
		task_waiter_wait4(&t[i], 3);

	test_msg("Checking result\n");

	/* check we can read all client messages */
	for (i = 0; i < PROCESSES_NUM; i++) {
		ret = read(srv, buf, sizeof(MSG));
		buf[ret > 0 ? ret : 0] = 0;
		if (ret != sizeof(MSG)) {
			fail("%d: %s", ret, buf);
			ret = 1;
			goto clean;
		}
	}

	ret = 0;
	pass();

clean:
	unlink(addr.sun_path);
	rmdir(dirname);
	return ret;
}
