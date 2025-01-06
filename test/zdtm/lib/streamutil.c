#include <errno.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>

#include "zdtmtst.h"

int set_nonblock(int fd, int on)
{
	int flag;

	flag = fcntl(fd, F_GETFL, 0);

	if (flag < 0)
		return flag;

	if (on)
		flag |= O_NONBLOCK;
	else
		flag &= ~O_NONBLOCK;

	return fcntl(fd, F_SETFL, flag);
}

int pipe_in2out(int infd, int outfd, uint8_t *buffer, int length)
{
	uint8_t *buf;
	int rlen, wlen;

	while (1) {
		rlen = read(infd, buffer, length);
		if (rlen <= 0)
			return rlen;

		/* don't go reading until we're done with writing */
		for (buf = buffer; rlen > 0; buf += wlen, rlen -= wlen) {
			wlen = write(outfd, buf, rlen);
			if (wlen < 0)
				return wlen;
		}
	}
}

int read_data(int fd, unsigned char *buf, int size)
{
	int cur = 0;
	int ret;
	while (cur != size) {
		ret = read(fd, buf + cur, size - cur);
		if (ret <= 0) {
			pr_perror("read(%d) = %d", size - cur, ret);
			return -1;
		}
		cur += ret;
	}

	return 0;
}

int write_data(int fd, const unsigned char *buf, int size)
{
	int cur = 0;
	int ret;

	while (cur != size) {
		ret = write(fd, buf + cur, size - cur);
		if (ret <= 0) {
			pr_perror("write(%d) = %d", size - cur, ret);
			return -1;
		}
		cur += ret;
	}

	return 0;
}
