#ifndef __CR_BROKER_H__
#define __CR_BROKER_H__

#include <errno.h>
#include <stddef.h>
#include <sys/socket.h>

static inline int send_broker_msg(int sock, const void *msg, size_t size)
{
	struct iovec iov = {
		.iov_base = (void *)msg,
		.iov_len = size,
	};
	struct msghdr hdr = {
		.msg_iov = &iov,
		.msg_iovlen = 1,
	};
	ssize_t ret;

	do {
		ret = sendmsg(sock, &hdr, MSG_NOSIGNAL);
	} while (ret < 0 && errno == EINTR);

	if (ret < 0)
		return -1;
	if ((size_t)ret != size) {
		errno = EMSGSIZE;
		return -1;
	}

	return 0;
}

static inline int recv_broker_msg(int sock, void *msg, size_t size)
{
	struct iovec iov = {
		.iov_base = msg,
		.iov_len = size,
	};
	struct msghdr hdr = {
		.msg_iov = &iov,
		.msg_iovlen = 1,
	};
	ssize_t ret;

	do {
		ret = recvmsg(sock, &hdr, 0);
	} while (ret < 0 && errno == EINTR);

	if (ret < 0)
		return -1;
	if (ret == 0) {
		errno = ECONNRESET;
		return -1;
	}
	if ((size_t)ret != size) {
		errno = EMSGSIZE;
		return -1;
	}

	return 0;
}

#endif /* __CR_BROKER_H__ */
