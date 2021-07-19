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
#include <sys/mman.h>

#include "zdtmtst.h"

const char *test_doc = "memfd mmap";
const char *test_author = "Nicolas Viennot <Nicolas.Viennot@twosigma.com>";

#define err(exitcode, msg, ...)                \
	({                                     \
		pr_perror(msg, ##__VA_ARGS__); \
		exit(exitcode);                \
	})

static int _memfd_create(const char *name, unsigned int flags)
{
	return syscall(SYS_memfd_create, name, flags);
}

int main(int argc, char *argv[])
{
#define LEN 6
	int fd;
	void *addr_shared, *addr_private;
	char buf[LEN];

	test_init(argc, argv);

	fd = _memfd_create("somename", MFD_CLOEXEC);
	if (fd < 0)
		err(1, "Can't call memfd_create");

	if (ftruncate(fd, LEN) < 0)
		err(1, "Can't truncate");

	addr_shared = mmap(NULL, LEN, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (addr_shared == MAP_FAILED)
		err(1, "Can't mmap");

	write(fd, "write1", LEN);

	addr_private = mmap(NULL, LEN, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
	if (addr_private == MAP_FAILED)
		err(1, "Can't mmap");

	test_daemon();
	test_waitsig();

	if (memcmp(addr_shared, "write1", LEN)) {
		fail("content mismatch (shared)");
		return 1;
	}

	strcpy(addr_shared, "write2");

	if (pread(fd, buf, LEN, 0) != LEN) {
		fail("read problem");
		return 1;
	}

	if (memcmp(buf, "write2", LEN)) {
		fail("content mismatch (shared)");
		return 1;
	}

	if (memcmp(addr_private, "write2", LEN)) {
		fail("content mismatch (private)");
		return 1;
	}

	strcpy(addr_private, "write3");

	if (memcmp(addr_shared, "write2", LEN)) {
		fail("content mismatch (shared)");
		return 1;
	}

	pass();

	return 0;
}
