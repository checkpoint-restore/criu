#include <linux/memfd.h>
#include <sys/mman.h>
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
#ifdef MEMFD05
	char path[PATH_MAX];
	char *addr_p, *addr_s;
	int rofd;
#endif
	int fd;

	test_init(argc, argv);

	fd = _memfd_create("somename", 0);
	if (fd < 0) {
		pr_perror("memfd_create()");
		return 1;
	}
	if (ftruncate(fd, script_len) == -1) {
		pr_perror("ftruncate");
		return 1;
	}
	if (write(fd, script, script_len) != script_len) {
		pr_perror("write(memfd)");
		return 1;
	}
#ifdef MEMFD05
	snprintf(path, PATH_MAX - 1, "/proc/self/fd/%d", fd);
	rofd = open(path, O_RDONLY);
	if (rofd < 0) {
		pr_perror("unable to open read-only memfd");
		return 1;
	}
	addr_p = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_FILE | MAP_PRIVATE, rofd, 0);
	if (addr_p == MAP_FAILED) {
		pr_perror("mmap");
		return 1;
	}
	addr_s = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_FILE | MAP_SHARED, fd, 0);
	if (addr_s == MAP_FAILED) {
		pr_perror("mmap");
		return 1;
	}
#endif

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
