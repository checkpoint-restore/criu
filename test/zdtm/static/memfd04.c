#include <linux/memfd.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>

#include "zdtmtst.h"

const char *test_doc = "exec(memfd)";
const char *test_author = "Michał Mirosław <emmir@google.com>";

static int _memfd_create(const char *name, unsigned int flags)
{
	return syscall(SYS_memfd_create, name, flags);
}

static int _execveat(int dirfd, const char *pathname, const char *const argv[], const char *const envp[], int flags)
{
	return syscall(SYS_execveat, dirfd, pathname, argv, envp, flags);
}

static const char *const script_argv[] = { "true", NULL };
static const char *const script_env[] = { NULL };

static bool test_exec_fd(int fd)
{
	int err, pid, status;

	err = fcntl(fd, F_GETFD);
	if (err < 0) {
		fail("fcntl(F_GETFD)");
		return false;
	}
	if (err) {
		errno = 0;
		fail("F_GETFD for the memfd returned %d but expected 0", err);
		return false;
	}

	pid = fork();
	if (!pid) {
		_execveat(fd, "", script_argv, script_env, AT_EMPTY_PATH);
		err = errno;
		pr_perror("execveat()");
		_exit(err);
	}

	if (pid < 0) {
		fail("fork()");
		return false;
	}

	while (waitpid(pid, &status, 0) != pid) {
		if (errno == EINTR)
			continue;
		fail("waitpid(child=%d)", pid);
		return false;
	}

	if (status != 0) {
		pr_err("child exited with status=%d\n", status);
		return false;
	}

	return true;
}

static const char script[] = "#!/bin/true";
static const size_t script_len = sizeof(script) - 1;

int main(int argc, char *argv[])
{
	int fd;

	test_init(argc, argv);

	fd = _memfd_create("somename", 0);
	if (fd < 0) {
		fail("memfd_create()");
		return 1;
	}

	if (write(fd, script, script_len) != script_len) {
		fail("write(memfd)");
		return 1;
	}

	if (!test_exec_fd(fd))
		return 1;

	test_msg("execveat(memfd) succeeded before C/R.\n");

	test_daemon();
	test_waitsig();

	if (!test_exec_fd(fd))
		return 1;

	pass();

	return 0;
}
