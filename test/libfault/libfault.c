#define _GNU_SOURCE
#include <unistd.h>
#include <dlfcn.h>
#include <errno.h>

ssize_t (*original_pread)(int fd, void *buf, size_t count, off_t offset) = NULL;

/**
 * This function is a wrapper around pread() that is used for testing CRIU's
 * handling of cases where pread() returns less data than requested.
 *
 * pmc_fill() in criu/pagemap.c is a good example of where this can happen.
 */
ssize_t pread64(int fd, void *buf, size_t count, off_t offset)
{
	if (!original_pread) {
		original_pread = dlsym(RTLD_NEXT, "pread");
		if (!original_pread) {
			errno = EIO;
			return -1;
		}
	}

	/* The following aims to simulate the case when pread() returns less
	 * data than requested. We need to ensure that CRIU handles such cases. */
	if (count > 2048) {
		count -= 1024;
	}

	return original_pread(fd, buf, count, offset);
}
