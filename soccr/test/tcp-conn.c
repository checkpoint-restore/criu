#include <sys/socket.h>
#include <arpa/inet.h> /* for srvaddr_in and inet_ntoa() */
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include "../soccr.h"
#include <stdarg.h>

#define pr_perror(fmt, ...) printf(fmt ": %m\n", ##__VA_ARGS__)

enum {
	TCP_NO_QUEUE,
	TCP_RECV_QUEUE,
	TCP_SEND_QUEUE,
	TCP_QUEUES_NR,
};
static void pr_printf(unsigned int level, const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	vprintf(fmt, args);
	va_end(args);
}

int main(void)
{
	union libsoccr_addr addr, dst;
	int srv, sock, clnt, rst;
	int ret, dsize;
	socklen_t dst_let;
	struct libsoccr_sk_data data = {};
	struct libsoccr_sk *so, *so_rst;
	char buf[11] = "0123456789", *queue;

	libsoccr_set_log(10, pr_printf);

	memset(&addr, 0, sizeof(addr));

#ifndef TEST_IPV6
	addr.v4.sin_family = AF_INET;
	inet_pton(AF_INET, "0.0.0.0", &(addr.v4.sin_addr));
#else
	addr.v6.sin6_family = AF_INET6;
	inet_pton(AF_INET6, "::0", &(addr.v6.sin6_addr));
#endif

#ifndef TEST_IPV6
	srv = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
#else
	srv = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
#endif
	if (srv == -1) {
		pr_perror("socket() failed");
		return -1;
	}

#ifndef TEST_IPV6
	addr.v4.sin_port = htons(8765);
#else
	addr.v6.sin6_port = htons(8765);
#endif
	ret = bind(srv, (struct sockaddr *)&addr, sizeof(addr));
	if (ret == -1) {
		pr_perror("bind() failed");
		return -1;
	}

	if (listen(srv, 1) == -1) {
		pr_perror("listen() failed");
		return -1;
	}

#ifndef TEST_IPV6
	clnt = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
#else
	clnt = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
#endif
	if (clnt == -1) {
		pr_perror("socket() failed");
		return -1;
	}

	if (connect(clnt, (struct sockaddr *)&addr, sizeof(addr))) {
		pr_perror("connect");
		return 1;
	}

	dst_let = sizeof(dst);
	sock = accept(srv, (struct sockaddr *)&dst, &dst_let);
	if (sock < 0) {
		pr_perror("accept");
		return 1;
	}

	if (write(clnt, &buf, sizeof(buf)) != sizeof(buf)) {
		pr_perror("write");
		return 1;
	}

	/* Start testing */
	dst_let = sizeof(addr);
	if (getsockname(sock, (struct sockaddr *)&addr, &dst_let)) {
		pr_perror("getsockname");
		return 1;
	}
	dst_let = sizeof(addr);
	if (getpeername(sock, (struct sockaddr *)&dst, &dst_let)) {
		pr_perror("getpeername");
		return 1;
	}

	so = libsoccr_pause(sock);

	dsize = libsoccr_save(so, &data, sizeof(data));
	if (dsize < 0) {
		pr_perror("libsoccr_save");
		return 1;
	}

#ifndef TEST_IPV6
	rst = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
#else
	rst = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
#endif
	if (rst == -1) {
		pr_perror("socket() failed");
		return -1;
	}
	close(sock);

	so_rst = libsoccr_pause(rst);
	libsoccr_set_addr(so_rst, 1, &addr, 0);
	libsoccr_set_addr(so_rst, 0, &dst, 0);

	queue = libsoccr_get_queue_bytes(so, TCP_RECV_QUEUE, SOCCR_MEM_EXCL);
	libsoccr_set_queue_bytes(so_rst, TCP_RECV_QUEUE, queue, SOCCR_MEM_EXCL);
	queue = libsoccr_get_queue_bytes(so, TCP_SEND_QUEUE, SOCCR_MEM_EXCL);
	libsoccr_set_queue_bytes(so_rst, TCP_SEND_QUEUE, queue, SOCCR_MEM_EXCL);

	ret = libsoccr_restore(so_rst, &data, dsize);
	if (ret) {
		pr_perror("libsoccr_restore: %d", ret);
		return 1;
	}

	libsoccr_resume(so_rst);
	libsoccr_resume(so);

	if (read(rst, &buf, sizeof(buf)) != sizeof(buf)) {
		pr_perror("read");
		return 1;
	}

	if (write(rst, &buf, sizeof(buf)) != sizeof(buf)) {
		pr_perror("write");
		return 1;
	}
	shutdown(rst, SHUT_WR);

	if (read(clnt, &buf, sizeof(buf)) != sizeof(buf)) {
		pr_perror("read");
		return 1;
	}

	return 0;
}
