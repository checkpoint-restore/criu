#define _GNU_SOURCE             /* See feature_test_macros(7) */
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sched.h>
#include <signal.h>
#include <sys/wait.h>
#include <stdlib.h>

#include "zdtmtst.h"

const char *test_doc	= "Check a shared file descriptor table.";
const char *test_author	= "Andrew Vagin <avagin@openvz.org>";

char *filename;
TEST_OPTION(filename, string, "file name", 1);

#define STACK_SIZE 4096
#define TEST_FD 128
#define TEST_STRING "Hello World!"

#define CHILDREN 4
static int fork_pfd[2];

static void forked()
{
	char c = 0;

	if (write(fork_pfd[1], &c, 1) != 1) {
		pr_perror("Unable to send a signal to the parent");
		exit(5);
	}
}

static void wait_children()
{
	int i;
	char c;

	for (i = 0; i < CHILDREN; i++) {
		if (read(fork_pfd[0], &c, 1) != 1) {
			pr_perror("Unable to read a signal from a child");
			exit(5);
		}
	}
}

static pid_t clone_child(int (*fn)(void *), int flags)
{
	char stack[STACK_SIZE];
	pid_t pid;

	pid = clone(fn, stack + STACK_SIZE,
			flags | SIGCHLD, NULL);
	if (pid == -1) {
		pr_perror("Unable to clone a new process");
		return -1;
	}

	return pid;
}

static int child2(void *_arg)
{
	char buf[10];

	forked();
	test_waitsig();

	if (read(TEST_FD, buf, sizeof(TEST_STRING)) != sizeof(TEST_STRING)) {
		pr_perror("Unable to read from %d", TEST_FD);
		return 1;
	}

	return 0;
}

static int child3(void *_arg)
{
	forked();
	test_waitsig();

	if (close(TEST_FD) != -1) {
		fail("%d is exist\n", TEST_FD);
		return 1;
	}

	return 0;
}

static int child(void *_arg)
{
	char buf[10];
	pid_t pid, pid2;
	int status;

	pid = clone_child(child2, CLONE_FILES);
	if (pid < 0)
		return 1;

	pid2 = clone_child(child3, 0);
	if (pid < 0)
		return 1;

	forked();
	test_waitsig();

	kill(pid2, SIGTERM);
	kill(pid, SIGTERM);
	waitpid(pid2, &status, 0);

	if (status) {
		fail("The child3 returned %d\n", status);
		return 1;
	}

	waitpid(pid, &status, 0);

	if (status) {
		fail("The child2 returned %d\n", status);
		return 1;
	}

	if (read(TEST_FD, buf, sizeof(TEST_STRING)) != sizeof(TEST_STRING)) {
		pr_perror("Unable to read from %d", TEST_FD);
		return 1;
	}

	if (close(TEST_FD) == -1) {
		pr_perror("Unable to close(%d)", TEST_FD);
		return 1;
	}

	return 0;
}

int main(int argc, char ** argv)
{
	int status;
	pid_t pid, pid2;
	int fd, i;

	test_init(argc, argv);

	if (pipe(fork_pfd)) {
		pr_perror("pipe");
		return 1;
	}

	pid = clone_child(child, CLONE_FILES);
	if (pid < 0)
		return 1;

	pid2 = clone_child(child2, CLONE_FILES);
	if (pid2 < 0)
		return 1;

	wait_children();

	test_daemon();
	test_waitsig();

	fd = open(filename, O_RDWR | O_CREAT, 0666);
	if (fd == -1) {
		pr_perror("Can't open /dev/zero");
		return -1;
	}

	for (i = 0; i < 3; i++)
		if (write(fd, TEST_STRING, sizeof(TEST_STRING)) != sizeof(TEST_STRING)) {
			pr_perror("Unable to write a test string");
			return -1;
		}

	fd = dup2(fd, TEST_FD);
	if (fd == -1) {
		pr_perror("Can't dup fd to %d", fd, TEST_FD);
		return -1;
	}

	lseek(fd, 0, SEEK_SET);

	kill(pid2, SIGTERM);
	waitpid(pid2, &status, 0);
	kill(pid, SIGTERM);

	if (status) {
		fail("The child returned %d\n", status);
		return 1;
	}

	waitpid(pid, &status, 0);
	if (status) {
		fail("The child returned %d\n", status);
		return 1;
	}

	if (close(TEST_FD) == 0) {
		fail("%d was not closed\n", TEST_FD);
		return 1;
	}

	pass();

	return 0;
}
