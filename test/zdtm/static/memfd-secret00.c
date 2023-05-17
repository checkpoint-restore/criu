#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "zdtmtst.h"

#define SECRET "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
#define SIZE   26

const char *test_doc = "memfd_secret file descriptor";
const char *test_author = "Dhanuka Warusadura <csx@tuta.io>";

#ifndef __NR_memfd_secret
#define __NR_memfd_secret 447
#endif

static int _memfd_secret(unsigned int flags)
{
	return syscall(__NR_memfd_secret, flags);
}

static void *secret_init(size_t size)
{
	int fd;
	void *secretmem = NULL;

	fd = _memfd_secret(0);
	if (fd < 0)
		return secretmem;

	if (ftruncate(fd, size) < 0) {
		close(fd);
		return secretmem;
	}

	secretmem = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (secretmem == MAP_FAILED) {
		close(fd);
		return secretmem;
	}

	return secretmem;
}

static void secret_fini(void *mem, size_t size)
{
	munmap(mem, size);
}

int main(int argc, char *argv[])
{
	char *secretmem;

	test_init(argc, argv);

	secretmem = secret_init(SIZE);
	if (!secretmem) {
		fail("memfd_secret: not supported operation");
		return 1;
	}

	memcpy(secretmem, SECRET, SIZE);

	test_daemon();
	test_waitsig();

	if (strncmp(secretmem, SECRET, SIZE)) {
		fail("secretmem content mismatch");
		return 1;
	}

	secret_fini(secretmem, SIZE);

	pass();

	return 0;
}
