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

const char *test_doc	= "Test unix dgram sockets\n";
const char *test_author	= "Cyrill Gorcunov <gorcunov@openvz.org";

#define SK_DATA_BOUND		"data-packet-bound"
#define SK_DATA_CONN		"data-packet-conn"
#define SK_DATA_BOUND_CONN	"data-packet-bound-conn"

char *filename;
TEST_OPTION(filename, string, "socket file name", 1);

int main(int argc, char *argv[])
{
	struct sockaddr_un name_bound;
	struct sockaddr_un name_conn;
	struct sockaddr_un name_bound_conn;
	int sk_dgram_bound_client;
	int sk_dgram_bound_server;
	int sk_dgram_conn_client;
	int sk_dgram_conn_client2;
	int sk_dgram_conn_server;
	int sk_dgram_bound_conn;

	char path[PATH_MAX];
	char buf[64];
	/*
	 * The original code makes dir to be current working
	 * directory. But it may be too long in google environment
	 * for path to be fit into struct sockaddr_un.
	 * One alternate way to resolve it is to use relative path
	 * for sockaddr_un, but criu has not supported relative
	 * bind path yet.
	 * We change it to "/tmp" to ensure its short length.
	 */
	char *dirname = "/tmp";

	int ret;

	test_init(argc, argv);

	snprintf(path, sizeof(path), "%s/%s", dirname, filename);
	unlink(path);

	sk_dgram_bound_client	= socket(AF_UNIX, SOCK_DGRAM, 0);
	sk_dgram_bound_server	= socket(AF_UNIX, SOCK_DGRAM, 0);
	sk_dgram_conn_client	= socket(AF_UNIX, SOCK_DGRAM, 0);
	sk_dgram_conn_client2	= socket(AF_UNIX, SOCK_DGRAM, 0);
	sk_dgram_conn_server	= socket(AF_UNIX, SOCK_DGRAM, 0);
	sk_dgram_bound_conn	= socket(AF_UNIX, SOCK_DGRAM, 0);

	if (sk_dgram_conn_server < 0	||
	    sk_dgram_bound_server < 0	||
	    sk_dgram_conn_client < 0	||
	    sk_dgram_conn_client2 < 0	||
	    sk_dgram_conn_server < 0	||
	    sk_dgram_bound_conn < 0) {
		fail("socket");
		exit(1);
	}

	snprintf(path, sizeof(path), "%s/%s.bound", dirname, filename);
	unlink(path);
	if (strlen(path) >= sizeof(name_bound.sun_path)) {
		fail("too long path");
		exit(1);
	}

	name_bound.sun_family = AF_UNIX;
	strncpy(name_bound.sun_path, path, sizeof(name_bound.sun_path));

	snprintf(path, sizeof(path), "%s/%s.conn", dirname, filename);
	unlink(path);
	if (strlen(path) >= sizeof(name_conn.sun_path)) {
		fail("too long path");
		exit(1);
	}

	name_conn.sun_family = AF_UNIX;
	strncpy(name_conn.sun_path, path, sizeof(name_conn.sun_path));

	snprintf(path, sizeof(path), "%s/%s.bound-conn", dirname, filename);
	unlink(path);
       if (strlen(path) >= sizeof(name_bound_conn.sun_path)) {
               fail("too long path");
               exit(1);
       }

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

	ret = connect(sk_dgram_conn_client, &name_conn, sizeof(name_conn));
	if (ret) {
		fail("connect");
		exit(1);
	}

	ret = connect(sk_dgram_conn_client2, &name_conn, sizeof(name_conn));
	if (ret) {
		fail("connect");
		exit(1);
	}

	ret = bind(sk_dgram_bound_conn, &name_bound_conn, sizeof(name_bound_conn));
	if (ret) {
		fail("bind");
		exit(1);
	}

	/* Note, it's already bound, so make it more idiotic! */
	ret = connect(sk_dgram_bound_conn, &name_bound_conn, sizeof(name_bound_conn));
	if (ret) {
		fail("connect");
		exit(1);
	}

	memset(buf, 0, sizeof(buf));
	sendto(sk_dgram_bound_client, SK_DATA_BOUND, sizeof(SK_DATA_BOUND), 0,
	       &name_bound, sizeof(name_bound));
	read(sk_dgram_bound_server, &buf, sizeof(buf));
	if (strcmp(buf, SK_DATA_BOUND)) {
		fail("data corrupted\n");
		exit(1);
	}
	test_msg("dgram-bound       : '%s'\n", buf);

	memset(buf, 0, sizeof(buf));
	write(sk_dgram_conn_client, SK_DATA_CONN, sizeof(SK_DATA_CONN));
	read(sk_dgram_conn_server, &buf, sizeof(buf));
	if (strcmp(buf, SK_DATA_CONN)) {
		fail("data corrupted\n");
		exit(1);
	}
	test_msg("dgram-conn        : '%s'\n", buf);

	memset(buf, 0, sizeof(buf));
	write(sk_dgram_bound_conn, SK_DATA_BOUND_CONN, sizeof(SK_DATA_BOUND_CONN));
	read(sk_dgram_bound_conn, &buf, sizeof(buf));
	if (strcmp(buf, SK_DATA_BOUND_CONN)) {
		fail("data corrupted\n");
		exit(1);
	}
	test_msg("dgram-bound-conn  : '%s'\n", buf);

	test_daemon();
	test_waitsig();

	memset(buf, 0, sizeof(buf));
	sendto(sk_dgram_bound_client, SK_DATA_BOUND, sizeof(SK_DATA_BOUND), 0,
	       &name_bound, sizeof(name_bound));
	read(sk_dgram_bound_server, &buf, sizeof(buf));
	if (strcmp(buf, SK_DATA_BOUND)) {
		fail("data corrupted\n");
		exit(1);
	}
	test_msg("dgram-bound       : '%s'\n", buf);

	memset(buf, 0, sizeof(buf));
	write(sk_dgram_conn_client, SK_DATA_CONN, sizeof(SK_DATA_CONN));
	read(sk_dgram_conn_server, &buf, sizeof(buf));
	if (strcmp(buf, SK_DATA_CONN)) {
		fail("data corrupted\n");
		exit(1);
	}
	test_msg("dgram-conn        : '%s'\n", buf);

	memset(buf, 0, sizeof(buf));
	write(sk_dgram_bound_conn, SK_DATA_BOUND_CONN, sizeof(SK_DATA_BOUND_CONN));
	read(sk_dgram_bound_conn, &buf, sizeof(buf));
	if (strcmp(buf, SK_DATA_BOUND_CONN)) {
		fail("data corrupted\n");
		exit(1);
	}
	test_msg("dgram-bound-conn  : '%s'\n", buf);

	pass();

	/*
	 * Do cleanup work
	 */
	unlink(name_bound.sun_path);
	unlink(name_conn.sun_path);
	unlink(name_bound_conn.sun_path);
	return 0;
}
