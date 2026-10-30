#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <sys/socket.h>
#include <arpa/inet.h> /* for srvaddr_in and inet_ntoa() */
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "../soccr.h"
#include <stdarg.h>

#define pr_perror(fmt, ...) printf(fmt ": %m\n", ##__VA_ARGS__)
static void pr_printf(unsigned int level, const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	vprintf(fmt, args);
	va_end(args);
}

static int cmp_addr(union libsoccr_addr *a, union libsoccr_addr *b)
{
	if (a->sa.sa_family == AF_INET)
		return memcmp(&a->v4, &b->v4, sizeof(a->v4));
	return memcmp(&a->v6, &b->v6, sizeof(a->v6));
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
	union libsoccr_addr *sa;

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

	if (libsoccr_get_fd(so) != sock) {
		printf("libsoccr_get_fd() returned %d, expected %d\n", libsoccr_get_fd(so), sock);
		return 1;
	}

	sa = libsoccr_get_addr(so, 1, 0);
	if (!sa || cmp_addr(sa, &addr)) {
		printf("libsoccr_get_addr() returned a wrong source address\n");
		return 1;
	}

	/* With SOCCR_MEM_EXCL the caller owns the address and has to free it */
	sa = libsoccr_get_addr(so, 0, SOCCR_MEM_EXCL);
	if (!sa || cmp_addr(sa, &dst)) {
		printf("libsoccr_get_addr() returned a wrong destination address\n");
		return 1;
	}
	free(sa);

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
	libsoccr_release(so);

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
