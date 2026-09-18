/* Test-only LD_PRELOAD shim; never linked into CRIU. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/uio.h>
#include <unistd.h>

static bool selected_image(int fd)
{
	const char *mode = getenv("CRIU_TEST_FAIL_IMAGE");
	const char *base;
	char proc[64], path[PATH_MAX];
	ssize_t size;

	if (!mode)
		return false;
	snprintf(proc, sizeof(proc), "/proc/self/fd/%d", fd);
	size = readlink(proc, path, sizeof(path) - 1);
	if (size < 0)
		return false;
	path[size] = '\0';
	base = strrchr(path, '/');
	if (!base)
		return false;
	base++;
	if (!strcmp(mode, "inventory"))
		return !strcmp(base, "inventory.img");
	if (!strcmp(mode, "pagemap")) {
		size_t length = strlen(base);

		return !strncmp(base, "pagemap-", 8) && length > 12 &&
		       !strcmp(base + length - 4, ".img");
	}
	return false;
}

ssize_t write(int fd, const void *data, size_t size)
{
	ssize_t (*real_write)(int, const void *, size_t);

	real_write = dlsym(RTLD_NEXT, "write");
	if (!real_write) {
		errno = EIO;
		return -1;
	}
	if (selected_image(fd)) {
		static const char message[] = "TEST_FAULT: image write rejected with ENOSPC\n";

		real_write(STDERR_FILENO, message, sizeof(message) - 1);
		errno = ENOSPC;
		return -1;
	}
	return real_write(fd, data, size);
}

ssize_t writev(int fd, const struct iovec *iov, int count)
{
	ssize_t (*real_writev)(int, const struct iovec *, int);

	real_writev = dlsym(RTLD_NEXT, "writev");
	if (!real_writev) {
		errno = EIO;
		return -1;
	}
	if (selected_image(fd)) {
		ssize_t (*real_write)(int, const void *, size_t);
		static const char message[] = "TEST_FAULT: image writev rejected with ENOSPC\n";

		real_write = dlsym(RTLD_NEXT, "write");
		if (real_write)
			real_write(STDERR_FILENO, message, sizeof(message) - 1);
		errno = ENOSPC;
		return -1;
	}
	return real_writev(fd, iov, count);
}

#include <stdint.h>
#include <sys/socket.h>

static void disconnect_now(int fd)
{
	ssize_t (*real_write)(int, const void *, size_t) = dlsym(RTLD_NEXT, "write");
	static const char message[] = "TEST_FAULT: page server disconnected\n";

	if (real_write)
		real_write(STDERR_FILENO, message, sizeof(message) - 1);
	shutdown(fd, SHUT_RDWR);
	_exit(73);
}

ssize_t recv(int fd, void *data, size_t size, int flags)
{
	ssize_t (*real_recv)(int, void *, size_t, int) = dlsym(RTLD_NEXT, "recv");
	const char *mode = getenv("CRIU_TEST_DISCONNECT");
	/* Match the native page-server frame layout, including ABI padding. */
	struct command_frame {
		uint32_t cmd;
		uint64_t nr_pages;
		uint64_t vaddr;
		uint64_t dst_id;
	};
	static struct command_frame frame;
	static size_t received;
	ssize_t ret;

	if (!real_recv) {
		errno = EIO;
		return -1;
	}
	ret = real_recv(fd, data, size, flags);
	/* Raw page payload uses splice(); recv() carries command frames only. */
	if (mode && !strcmp(mode, "close") && ret > 0 && size == sizeof(frame) - received) {
		memcpy((char *)&frame + received, data, ret);
		received += ret;
		if (received == sizeof(frame)) {
			received = 0;
			if ((frame.cmd & 0xffff) == 0x1023 || (frame.cmd & 0xffff) == 0x1024)
				disconnect_now(fd);
		}
	}
	return ret;
}

ssize_t splice(int in, off_t *in_off, int out, off_t *out_off, size_t size, unsigned int flags)
{
	ssize_t (*real_splice)(int, off_t *, int, off_t *, size_t, unsigned int);
	const char *mode = getenv("CRIU_TEST_DISCONNECT");
	static size_t received;
	int type;
	socklen_t len = sizeof(type);
	bool selected = mode && !strcmp(mode, "transfer") &&
			!getsockopt(in, SOL_SOCKET, SO_TYPE, &type, &len);
	ssize_t ret;

	real_splice = dlsym(RTLD_NEXT, "splice");
	if (!real_splice) {
		errno = EIO;
		return -1;
	}
	if (selected && received >= 8192)
		disconnect_now(in);
	ret = real_splice(in, in_off, out, out_off, size, flags);
	if (selected && ret > 0)
		received += ret;
	return ret;
}
