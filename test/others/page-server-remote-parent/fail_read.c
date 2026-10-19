/* Test-only LD_PRELOAD shim; real short reads copy exactly their return count. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/uio.h>
#include <unistd.h>

static uintptr_t selected;
static unsigned int calls;
static bool spliced;

static void log_fault(const char *mode, const char *event, uintptr_t address)
{
	fprintf(stderr, "READ_FAULT: %s %s %#lx\n", mode, event, (unsigned long)address);
}

ssize_t process_vm_readv(pid_t pid, const struct iovec *local, unsigned long local_count,
			 const struct iovec *remote, unsigned long remote_count, unsigned long flags)
{
	ssize_t (*real_read)(pid_t, const struct iovec *, unsigned long, const struct iovec *,
			     unsigned long, unsigned long) = dlsym(RTLD_NEXT, "process_vm_readv");
	const char *mode = getenv("CRIU_TEST_READ_FAULT");
	const char *target = getenv("CRIU_TEST_READ_PID");
	const char *begin = getenv("CRIU_TEST_READ_BEGIN");
	const char *end = getenv("CRIU_TEST_READ_END");
	size_t page = sysconf(_SC_PAGESIZE);
	uintptr_t base;
	struct iovec prefix;
	ssize_t ret;

	if (!real_read) {
		errno = ENOSYS;
		return -1;
	}
	if (!mode || !target || !begin || !end || pid != (pid_t)strtol(target, NULL, 0) || !remote_count)
		goto normal;
	base = (uintptr_t)remote[0].iov_base;
	/* Select the first iovec of a batch, wholly inside the known private VMA. */
	if (!selected && base >= strtoull(begin, NULL, 0) &&
	    base + remote[0].iov_len <= strtoull(end, NULL, 0) && remote[0].iov_len >= 3 * page) {
		selected = base + (!strcmp(mode, "partial-efault") ? page : 0);
		log_fault(mode, "armed", selected);
	}
	if (!selected)
		goto normal;
	if (!strcmp(mode, "short-read")) {
		if (calls++)
			goto normal;
		prefix = remote[0];
		prefix.iov_len = page;
		ret = real_read(pid, local, local_count, &prefix, 1, flags);
		if (ret == (ssize_t)page)
			log_fault(mode, "short", selected);
		return ret;
	}
	if (!strcmp(mode, "recovery-eperm") || !strcmp(mode, "recovery-esrch") ||
	    !strcmp(mode, "recovery-zero")) {
		if (base < selected || base >= selected + remote[0].iov_len)
			goto normal;
		if (!calls++) {
			log_fault(mode, "efault", selected);
			errno = EFAULT;
			return -1;
		}
		log_fault(mode, "recovery", selected);
		if (!strcmp(mode, "recovery-zero"))
			return 0;
		errno = !strcmp(mode, "recovery-esrch") ? ESRCH : EPERM;
		return -1;
	}
	if (!strcmp(mode, "zero-read")) {
		log_fault(mode, "zero", selected);
		return 0;
	}
	if (strcmp(mode, "first-efault") && strcmp(mode, "partial-efault"))
		goto normal;
	if (base <= selected && base + remote[0].iov_len > selected) {
		if (base < selected) {
			prefix = remote[0];
			prefix.iov_len = selected - base;
			ret = real_read(pid, local, local_count, &prefix, 1, flags);
			if (ret == (ssize_t)prefix.iov_len)
				log_fault(mode, "short", selected);
			return ret;
		}
		log_fault(mode, "efault", selected);
		errno = EFAULT;
		return -1;
	}
normal:
	return real_read(pid, local, local_count, remote, remote_count, flags);
}

ssize_t vmsplice(int fd, const struct iovec *iov, size_t count, unsigned int flags)
{
	ssize_t (*real_splice)(int, const struct iovec *, size_t, unsigned int) = dlsym(RTLD_NEXT, "vmsplice");
	const char *mode = getenv("CRIU_TEST_READ_FAULT");
	struct iovec prefix;
	size_t page = sysconf(_SC_PAGESIZE);
	ssize_t ret;

	if (!real_splice) {
		errno = ENOSYS;
		return -1;
	}
	/* Only the read-pre-dump path gifts a single user-buffer iovec. */
	if (!spliced && mode && count == 1 && iov[0].iov_len > page &&
	    (flags & (SPLICE_F_NONBLOCK | SPLICE_F_GIFT)) == (SPLICE_F_NONBLOCK | SPLICE_F_GIFT)) {
		if (!strcmp(mode, "vmsplice-error")) {
			spliced = true;
			log_fault(mode, "error", 0);
			errno = EIO;
			return -1;
		}
		if (!strcmp(mode, "vmsplice-short")) {
			spliced = true;
			prefix = iov[0];
			prefix.iov_len = page;
			ret = real_splice(fd, &prefix, 1, flags);
			if (ret == (ssize_t)page)
				log_fault(mode, "short", 0);
			return ret;
		}
	}
	return real_splice(fd, iov, count, flags);
}
