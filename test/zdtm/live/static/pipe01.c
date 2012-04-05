#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <linux/limits.h>

#include "zdtmtst.h"

const char *test_doc	= "Test that all data can be restored";
const char *test_author	= "Andrey Vagin <avagin@parallels.com>";

#define TEST_STRING "Hello world"

int main(int argc, char ** argv)
{
	int pfd[2], pfd_dup[2], pfd_rop[2];
	char path[PATH_MAX];
	int ret;
	uint8_t buf[4096];
	uint32_t crc;
	int flags, size = 0;

	test_init(argc, argv);

	crc = ~0;
	datagen(buf, sizeof(buf), &crc);

	ret = pipe(pfd);
	if (ret) {
		err("pipe() failed: %m");
		return 1;
	}

	pfd_dup[0] = dup(pfd[0]);
	pfd_dup[1] = dup(pfd[1]);

	snprintf(path, PATH_MAX, "/proc/self/fd/%d", pfd[0]);
	pfd_rop[0] = open(path, O_RDONLY);
	snprintf(path, PATH_MAX, "/proc/self/fd/%d", pfd[1]);
	pfd_rop[1] = open(path, O_WRONLY);

	if (pfd_rop[0] == -1 || pfd_rop[1] == -1 ||
	    pfd_dup[0] == -1 || pfd_dup[1] == -1) {
		err("dup() failed");
		return 1;
	}

	flags = fcntl(pfd[1], F_GETFL, 0);
	if (flags == -1) {
		err("fcntl() failed");
		return 1;
	}

	ret = fcntl(pfd[1], F_SETFL, flags | O_NONBLOCK);
	if (ret == -1) {
		err("fcntl() failed");
		return 1;
	}

	while (1) {
		ret = write(pfd[1], buf, sizeof(buf));
		if (ret == -1) {
			if (errno == EAGAIN)
				break;
			err("write() failed: %m");
			goto err;
		}

		size += ret;
	}

	test_daemon();

	test_waitsig();

	flags = fcntl(pfd[1], F_GETFL, 0);
	if (!(flags & O_NONBLOCK)) {
		err("O_NONBLOCK is absent");
		goto err;
	}

	flags = fcntl(pfd_dup[1], F_GETFL, 0);
	if (!(flags & O_NONBLOCK)) {
		err("O_NONBLOCK is absent");
		goto err;
	}

	flags = fcntl(pfd_rop[1], F_GETFL, 0);
	if (flags & O_NONBLOCK) {
		err("O_NONBLOCK appeared");
		goto err;
	}

	if (close(pfd[1]) == -1) {
		err("close() failed");
		goto err;
	}

	close(pfd_dup[1]);
	close(pfd_rop[1]);

	while (1) {
		ret = read(pfd[0], buf, sizeof(buf));
		if (ret == 0)
			break;
		if (ret == -1) {
			goto err;
			err("read() failed: %m");
		}
		size -= ret;

		crc = ~0;
		ret = datachk(buf, sizeof(buf), &crc);
		if (ret) {
			fail("CRC mismatch\n");
			goto err;
		}
	}

	if (size)
		goto err;

	pass();
	return 0;
err:
	fail();
	return 1;
}
