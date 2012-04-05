
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <limits.h>
#include <fcntl.h>

#include "zdtmtst.h"

/* FIXME Need gram sockets tests */

const char *test_doc	= "Test unix stream sockets\n";
const char *test_author	= "Cyrill Gorcunov <gorcunov@openvz.org";

#define SK_DATA "packet"

#define SK_DATA_BOUND		"data-packet-bound"
#define SK_DATA_CONN		"data-packet-conn"
#define SK_DATA_BOUND_CONN	"data-packet-bound-conn"

int main(int argc, char *argv[])
{
	int ssk_icon[4];
	int ssk_pair[2];
	struct sockaddr_un addr;
	struct sockaddr_un name_bound;
	struct sockaddr_un name_conn;
	struct sockaddr_un name_bound_conn;
	int sk_dgram_bound_client;
	int sk_dgram_bound_server;
	int sk_dgram_conn_client;
	int sk_dgram_conn_server;
	int sk_dgram_bound_conn;
	unsigned int addrlen;

	char path[PATH_MAX];
	char buf[64];
	char *cwd;

	int ret;

	test_init(argc, argv);

	cwd = get_current_dir_name();
	if (!cwd) {
		fail("getcwd\n");
		exit(1);
	}

	snprintf(path, sizeof(path), "%s/test-socket", cwd);
	unlink(path);

	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, path, sizeof(addr.sun_path));
	addrlen = sizeof(addr.sun_family) + strlen(path);

	ssk_icon[0] = socket(AF_UNIX, SOCK_STREAM, 0);
	ssk_icon[1] = socket(AF_UNIX, SOCK_STREAM, 0);
	ssk_icon[2] = socket(AF_UNIX, SOCK_STREAM, 0);
	if (ssk_icon[0] < 0 || ssk_icon[1] < 0 || ssk_icon[2] < 0) {
		fail("socket\n");
		exit(1);
	}

	ret = bind(ssk_icon[0], &addr, addrlen);
	if (ret) {
		fail("bind\n");
		exit(1);
	}

	ret = listen(ssk_icon[0], 16);
	if (ret) {
		fail("bind\n");
		exit(1);
	}

	ret = connect(ssk_icon[2], &addr, addrlen);
	if (ret) {
		fail("connect\n");
		exit(1);
	}

	ssk_icon[3] = accept(ssk_icon[0], NULL, NULL);
	if (ssk_icon[3] < 0) {
		fail("accept");
		exit(1);
	}

	ret = connect(ssk_icon[1], &addr, addrlen);
	if (ret) {
		fail("connect\n");
		exit(1);
	}

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, ssk_pair) == -1) {
		fail("socketpair\n");
		exit(1);
	}

	sk_dgram_bound_client	= socket(AF_UNIX, SOCK_DGRAM, 0);
	sk_dgram_bound_server	= socket(AF_UNIX, SOCK_DGRAM, 0);
	sk_dgram_conn_client	= socket(AF_UNIX, SOCK_DGRAM, 0);
	sk_dgram_conn_server	= socket(AF_UNIX, SOCK_DGRAM, 0);
	sk_dgram_bound_conn	= socket(AF_UNIX, SOCK_DGRAM, 0);

	if (sk_dgram_conn_server < 0	||
	    sk_dgram_bound_server < 0	||
	    sk_dgram_conn_client < 0	||
	    sk_dgram_conn_server < 0	||
	    sk_dgram_bound_conn < 0) {
		fail("socket");
		exit(1);
	}

	snprintf(path, sizeof(path), "%s/test-socket-bound", cwd);
	unlink(path);

	name_bound.sun_family = AF_UNIX;
	strncpy(name_bound.sun_path, path, sizeof(name_bound.sun_path));

	snprintf(path, sizeof(path), "%s/test-socket-conn", cwd);
	unlink(path);

	name_conn.sun_family = AF_UNIX;
	strncpy(name_conn.sun_path, path, sizeof(name_conn.sun_path));

	snprintf(path, sizeof(path), "%s/test-socket-bound-conn", cwd);
	unlink(path);

	name_bound_conn.sun_family = AF_UNIX;
	strncpy(name_bound_conn.sun_path, path, sizeof(name_bound_conn.sun_path));

	ret = bind(sk_dgram_bound_server, &name_bound, sizeof(name_bound));
	if (ret) {
		fail("bind");
		exit(1);
	}

	ret = bind(sk_dgram_conn_server, &name_conn, sizeof(name_conn));
	if (ret) {
		fail("bind");
		exit(1);
	}

	ret = bind(sk_dgram_bound_conn, &name_bound_conn, sizeof(name_bound_conn));
	if (ret) {
		fail("bind");
		exit(1);
	}

	ret = connect(sk_dgram_conn_client, &name_conn, sizeof(name_conn));
	if (ret) {
		fail("connect");
		exit(1);
	}

	ret = connect(sk_dgram_bound_conn, &name_bound_conn, sizeof(name_bound_conn));
	if (ret) {
		fail("connect");
		exit(1);
	}

	write(ssk_pair[0], SK_DATA, sizeof(SK_DATA));
	read(ssk_pair[1], &buf, sizeof(buf));
	if (strcmp(buf, SK_DATA)) {
		fail("data corrupted\n");
		exit(1);
	}
	test_msg("stream            : '%s'\n", buf);

	sendto(sk_dgram_bound_client, SK_DATA_BOUND, sizeof(SK_DATA_BOUND), 0,
	       &name_bound, sizeof(name_bound));
	read(sk_dgram_bound_server, &buf, sizeof(buf));
	if (strcmp(buf, SK_DATA_BOUND)) {
		fail("data corrupted\n");
		exit(1);
	}
	test_msg("dgram-bound       : '%s'\n", buf);

	write(sk_dgram_conn_client, SK_DATA_CONN, sizeof(SK_DATA_CONN));
	read(sk_dgram_conn_server, &buf, sizeof(buf));
	if (strcmp(buf, SK_DATA_CONN)) {
		fail("data corrupted\n");
		exit(1);
	}
	test_msg("dgram-conn        : '%s'\n", buf);

	write(sk_dgram_bound_conn, SK_DATA_BOUND_CONN, sizeof(SK_DATA_BOUND_CONN));
	read(sk_dgram_bound_conn, &buf, sizeof(buf));
	if (strcmp(buf, SK_DATA_BOUND_CONN)) {
		fail("data corrupted\n");
		exit(1);
	}
	test_msg("dgram-bound-conn  : '%s'\n", buf);

	test_daemon();
	test_waitsig();

	write(ssk_pair[0], SK_DATA, sizeof(SK_DATA));
	read(ssk_pair[1], &buf, sizeof(buf));
	if (strcmp(buf, SK_DATA)) {
		fail("data corrupted\n");
		exit(1);
	}
	test_msg("stream            : '%s'\n", buf);

	ret = accept(ssk_icon[0], NULL, NULL);
	if (ret < 0) {
		fail("accept\n");
		exit(1);
	}

	write(ssk_icon[1], SK_DATA, sizeof(SK_DATA));
	read(ret, &buf, sizeof(buf));
	if (strcmp(buf, SK_DATA)) {
		fail("data corrupted\n");
		exit(1);
	}
	test_msg("stream            : '%s'\n", buf);

	write(ssk_icon[2], SK_DATA, sizeof(SK_DATA));
	read(ssk_icon[3], &buf, sizeof(buf));
	if (strcmp(buf, SK_DATA)) {
		fail("data corrupted\n");
		exit(1);
	}
	test_msg("stream2           : '%s'\n", buf);

	sendto(sk_dgram_bound_client, SK_DATA_BOUND, sizeof(SK_DATA_BOUND), 0,
	       &name_bound, sizeof(name_bound));
	read(sk_dgram_bound_server, &buf, sizeof(buf));
	if (strcmp(buf, SK_DATA_BOUND)) {
		fail("data corrupted\n");
		exit(1);
	}
	test_msg("dgram-bound       : '%s'\n", buf);

	write(sk_dgram_conn_client, SK_DATA_CONN, sizeof(SK_DATA_CONN));
	read(sk_dgram_conn_server, &buf, sizeof(buf));
	if (strcmp(buf, SK_DATA_CONN)) {
		fail("data corrupted\n");
		exit(1);
	}
	test_msg("dgram-conn        : '%s'\n", buf);

	write(sk_dgram_bound_conn, SK_DATA_BOUND_CONN, sizeof(SK_DATA_BOUND_CONN));
	read(sk_dgram_bound_conn, &buf, sizeof(buf));
	if (strcmp(buf, SK_DATA_BOUND_CONN)) {
		fail("data corrupted\n");
		exit(1);
	}
	test_msg("dgram-bound-conn  : '%s'\n", buf);

	pass();
	return 0;
}
