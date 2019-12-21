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

const char *test_doc	= "memfd seals";
const char *test_author	= "Nicolas Viennot <Nicolas.Viennot@twosigma.com>";

#define err(exitcode, msg, ...) ({ pr_perror(msg, ##__VA_ARGS__); exit(exitcode); })

static int _memfd_create(const char *name, unsigned int flags)
{
	return syscall(SYS_memfd_create, name, flags);
}


#ifndef F_LINUX_SPECIFIC_BASE
# define F_LINUX_SPECIFIC_BASE	1024
#endif

#ifndef F_ADD_SEALS
  #define F_ADD_SEALS (F_LINUX_SPECIFIC_BASE + 9)
#endif

#ifndef F_GET_SEALS
  #define F_GET_SEALS (F_LINUX_SPECIFIC_BASE + 10)
#endif


#ifndef F_SEAL_SEAL
#define F_SEAL_SEAL	0x0001	/* prevent further seals from being set */
#define F_SEAL_SHRINK	0x0002	/* prevent file from shrinking */
#define F_SEAL_GROW	0x0004	/* prevent file from growing */
#define F_SEAL_WRITE	0x0008	/* prevent writes */
#endif

int main(int argc, char *argv[])
{
#define LEN 5
	int fd, fd2;
	void *addr_write, *addr_read;
	char fdpath[100];

	test_init(argc, argv);

	fd = _memfd_create("somename", MFD_ALLOW_SEALING | MFD_CLOEXEC);
	if (fd < 0)
		err(1, "Can't call memfd_create");

	if (write(fd, "hello", LEN) != LEN)
		err(1, "Can't write");

	if (fcntl(fd, F_ADD_SEALS, F_SEAL_WRITE) < 0)
		err(1, "Can't add seals");

	test_daemon();
	test_waitsig();

	snprintf(fdpath, sizeof(fdpath), "/proc/self/fd/%d", fd);
	fd2 = open(fdpath, O_RDWR);
	if (fd2 < 0)
		err(1, "Can't open memfd via proc");

	if (fcntl(fd, F_GET_SEALS) != F_SEAL_WRITE) {
		fail("Seals are different");
		return 1;
	}

	addr_write = mmap(NULL, LEN, PROT_WRITE, MAP_SHARED, fd2, 0);
	if (addr_write != MAP_FAILED) {
		fail("Should not be able to get write access");
		return 1;
	}

	addr_read = mmap(NULL, 1, PROT_READ, MAP_PRIVATE, fd2, 0);
	if (addr_read == MAP_FAILED)
		err(1, "Can't mmap");

	if (memcmp(addr_read, "hello", LEN)) {
		fail("Mapping has bad data");
		return 1;
	}

	pass();

	return 0;
}
