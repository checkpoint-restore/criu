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

#ifndef MFD_HUGETLB
#define MFD_HUGETLB 4
#endif

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
#ifdef ZDTM_HUGETLB
#define LEN (2 * (1 << 20)) /* 2MB */
#else
#define LEN 6
#endif

	int fd, flag = 0;
	void *addr_shared, *addr_private;
	char buf[LEN];
	dev_t dev1, dev2;

	test_init(argc, argv);

#ifdef ZDTM_HUGETLB
	flag = MFD_HUGETLB;
#endif

	fd = _memfd_create("somename", MFD_CLOEXEC | flag);
	if (fd < 0)
		err(1, "Can't call memfd_create");

	if (ftruncate(fd, LEN) < 0)
		err(1, "Can't truncate");

	addr_shared = mmap(NULL, LEN, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (addr_shared == MAP_FAILED)
		err(1, "Can't mmap");

	dev1 = get_mapping_dev(addr_shared);
	if (dev1 == (dev_t)-1) {
		fail("Can't get mapping dev");
		return 1;
	}

#ifdef ZDTM_HUGETLB
	strcpy(addr_shared, "write1");
#else
	write(fd, "write1", LEN);
#endif

	addr_private = mmap(NULL, LEN, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
	if (addr_private == MAP_FAILED)
		err(1, "Can't mmap");

	dev2 = get_mapping_dev(addr_private);
	if (dev2 == (dev_t)-1) {
		fail("Can't get mapping dev");
		return 1;
	}

	test_daemon();
	test_waitsig();

	if (strncmp(addr_shared, "write1", LEN)) {
		fail("content mismatch (shared)");
		return 1;
	}

	strcpy(addr_shared, "write2");

	if (pread(fd, buf, LEN, 0) != LEN) {
		fail("read problem");
		return 1;
	}

	if (strncmp(buf, "write2", LEN)) {
		fail("content mismatch (shared)");
		return 1;
	}

	if (strncmp(addr_private, "write2", LEN)) {
		fail("content mismatch (private)");
		return 1;
	}

	strcpy(addr_private, "write3");

	if (strncmp(addr_shared, "write2", LEN)) {
		fail("content mismatch (shared)");
		return 1;
	}

	if (dev1 != get_mapping_dev(addr_shared)) {
		fail("Mapping dev mismatch");
		return 1;
	}

	if (dev2 != get_mapping_dev(addr_private)) {
		fail("Mapping dev mismatch");
		return 1;
	}

	pass();

	return 0;
}
