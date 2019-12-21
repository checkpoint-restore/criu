#include <fcntl.h>
#include <linux/memfd.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/vfs.h>
#include <unistd.h>

#include "zdtmtst.h"

const char *test_doc	= "memfd file descriptor";
const char *test_author	= "Nicolas Viennot <Nicolas.Viennot@twosigma.com>";

#define err(exitcode, msg, ...) ({ pr_perror(msg, ##__VA_ARGS__); exit(exitcode); })

static int _memfd_create(const char *name, unsigned int flags)
{
	return syscall(SYS_memfd_create, name, flags);
}

int main(int argc, char *argv[])
{
	int fd, fl_flags1, fl_flags2, fd_flags1, fd_flags2;
	struct statfs statfs1, statfs2;
	off_t pos1, pos2;
	char buf[5];

	test_init(argc, argv);

	fd = _memfd_create("somename", MFD_CLOEXEC);
	if (fd < 0)
		err(1, "Can't call memfd_create");

	if (fcntl(fd, F_SETFL, O_APPEND) < 0)
		err(1, "Can't get fl flags");

	if ((fl_flags1 = fcntl(fd, F_GETFL)) == -1)
		err(1, "Can't get fl flags");

	if ((fd_flags1 = fcntl(fd, F_GETFD)) == -1)
		err(1, "Can't get fd flags");

	if (fstatfs(fd, &statfs1) < 0)
		err(1, "statfs issue");

	if (write(fd, "hello", 5) != 5)
		err(1, "write error");

	pos1 = 3;
	if (lseek(fd, pos1, SEEK_SET) < 0)
		err(1, "seek error");

	test_daemon();
	test_waitsig();

	if ((fl_flags2 = fcntl(fd, F_GETFL)) == -1)
		err(1, "Can't get fl flags");

	if (fl_flags1 != fl_flags2) {
		fail("fl flags differs");
		return 1;
	}

	if ((fd_flags2 = fcntl(fd, F_GETFD)) == -1)
		err(1, "Can't get fd flags");

	if (fd_flags1 != fd_flags2) {
		fail("fd flags differs");
		return 1;
	}

	if (fstatfs(fd, &statfs2) < 0)
		err(1, "statfs issue");

	if (statfs1.f_type != statfs2.f_type) {
		fail("statfs.f_type differs");
		return 1;
	}

	pos2 = lseek(fd, 0, SEEK_CUR);
	if (pos1 != pos2) {
		fail("position differs");
		return 1;
	}

	if (pread(fd, buf, sizeof(buf), 0) != sizeof(buf)) {
		fail("read problem");
		return 1;
	}

	if (memcmp(buf, "hello", sizeof(buf))) {
		fail("content mismatch");
		return 1;
	}

	pass();

	return 0;
}
