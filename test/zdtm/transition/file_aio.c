#include "zdtmtst.h"

const char *test_doc    = "test for AIO";
const char *test_author = "Andrew Vagin <avagin@parallels.com>";

#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <aio.h>

#define BUF_SIZE 1024

int main(int argc, char **argv)
{
	char buf[BUF_SIZE];
	int fd;
	struct aiocb aiocb;
	const struct aiocb   *aioary[1];
	char tmpfname[256]="/tmp/file_aio.XXXXXX";
	int ret;

	test_init(argc, argv);

	fd = mkstemp(tmpfname);
	if (fd == -1) {
		pr_perror("mkstemp() failed");
		exit(1);
	}

	unlink(tmpfname);

	if (write(fd, buf, BUF_SIZE) != BUF_SIZE) {
		pr_perror("Error at write()");
		exit(1);
	}

	test_daemon();

	while (test_go()) {
		memset(&aiocb, 0, sizeof(struct aiocb));
		aiocb.aio_offset = 0;
		aiocb.aio_fildes = fd;
		aiocb.aio_buf = buf;
		aiocb.aio_nbytes = BUF_SIZE;

		ret = aio_read(&aiocb);
		if (ret < 0) {
			if ((errno == EINTR) && (!test_go()))
				break;
			pr_perror("aio_read failed");
			return 1;
		}

		if (ret < 0) {
			pr_perror("aio_read failed");
			exit(1);
		}
		/* Wait for request completion */
		aioary[0] = &aiocb;
again:
		ret = aio_suspend(aioary, 1, NULL);
		if (ret < 0) {
			if ((errno == EINTR) && (! test_go()))
				break;
			if (errno != EINTR) {
				pr_perror("aio_suspend failed");
				return 1;
			}
		}

		ret = aio_error(&aiocb);
		if (ret == EINPROGRESS) {
#ifdef DEBUG
			test_msg("restart aio_suspend\n");
#endif
			goto again;
		}
		if (ret != 0) {
			pr_err("Error at aio_error(): %s\n", strerror(ret));
			return 1;
		}

		ret = aio_return(&aiocb);
		if (ret < 0) {
			if ((errno == EINTR) && (!test_go()))
				break;
			pr_perror("aio_return failed");
			return 1;
		}
		if (ret != BUF_SIZE) {
			pr_perror("Error at aio_return()");
			exit(1);
		}
	}
	close(fd);
	pass();
	return 0;
}
