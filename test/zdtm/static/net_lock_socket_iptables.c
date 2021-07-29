#include "zdtmtst.h"

#if defined(ZDTM_IPV6)
#define ZDTM_FAMILY AF_INET6
#else
#define ZDTM_FAMILY AF_INET
#endif

const char *test_doc = "Check that sockets are locked between dump and restore\n";
const char *test_author = "Zeyad Yasser <zeyady98@gmail.com>";

#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <sys/socket.h>

static int port = 8880;
#define SYNCFILE_PATH "socket_lock.sync"

int main(int argc, char **argv)
{
	char buf[5];
	int fd_s, fd_sock, buf_len;
	FILE *f_sync;

	test_init(argc, argv);

	if ((fd_s = tcp_init_server(ZDTM_FAMILY, &port)) < 0) {
		pr_err("initializing server failed\n");
		return 1;
	}

	// Server is ready to accept sockets
	f_sync = fopen(SYNCFILE_PATH, "w");
	if (f_sync == NULL) {
		pr_perror("cannot create sync file");
		return 1;
	}
#if defined(ZDTM_IPV6)
	if (fprintf(f_sync, "ipv6") < 0) {
#else
	if (fprintf(f_sync, "ipv4") < 0) {
#endif
		pr_perror("cannot write to sync file");
		return 1;
	}
	fclose(f_sync);

	fd_sock = tcp_accept_server(fd_s);

	test_daemon();
	test_waitsig();

	buf_len = recv(fd_sock, buf, 3, MSG_WAITALL);
	if (buf_len < 0) {
		pr_perror("read less then have to");
		return 1;
	}

	if (!strncmp(buf, "ABC", 3))
		pass();
	else
		fail();

	close(fd_sock);
	close(fd_s);

	return 0;
}
