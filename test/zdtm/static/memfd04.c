#include <fcntl.h>
#include <linux/memfd.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#include "zdtmtst.h"

const char *test_doc = "memfd file descriptor sharing";
const char *test_author = "Michał Mirosław <emmir@google.com>";

static int _memfd_create(const char *name, unsigned int flags)
{
	return syscall(SYS_memfd_create, name, flags);
}

#ifndef KCMP_FILE
#define KCMP_FILE 0
#endif

static int kcmp_fd(int fd1, int fd2)
{
	pid_t pid = getpid();
	return syscall(SYS_kcmp, pid, pid, KCMP_FILE, fd1, fd2);
}

#define CHECK(call) \
	if (((call)) < 0) { \
		fail(#call); \
		return 1; \
	}

static int check_fd_sharing(int orig_fd, int dup_fd, int open_fd)
{
	int cmp1, cmp2;

	CHECK(cmp1 = kcmp_fd(orig_fd, dup_fd));
	if (cmp1)
		fail("dup()ed fd is reported not the same as original");

	CHECK(cmp2 = kcmp_fd(orig_fd, open_fd));
	if (!cmp2)
		fail("re-open()ed fd is reported the same as original");

	return cmp1 || !cmp2;
}

int main(int argc, char *argv[])
{
	int orig_fd, dup_fd, open_fd;
	char path[64];

	test_init(argc, argv);

	CHECK(orig_fd = _memfd_create("foo", 0));
	CHECK(dup_fd = dup(orig_fd));
	sprintf(path, "/proc/self/fd/%d", orig_fd);
	CHECK(open_fd = open(path, O_RDWR));

	if (check_fd_sharing(orig_fd, dup_fd, open_fd))
		return 1;

	test_daemon();
	test_waitsig();

	if (check_fd_sharing(orig_fd, dup_fd, open_fd))
		return 1;

	pass();
	return 0;
}
