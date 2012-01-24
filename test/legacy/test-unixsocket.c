#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/un.h>

#define SK_NAME_BOUND		"test-socket-bound"
#define SK_NAME_CONN		"test-socket-conn"
#define SK_NAME_BOUND_CONN	"test-socket-bound-conn"

#define SK_DATA_PAIR		"data-packet-pair"
#define SK_DATA_BOUND		"data-packet-bound"
#define SK_DATA_CONN		"data-packet-conn"
#define SK_DATA_BOUND_CONN	"data-packet-bound-conn"

int main(void)
{
	struct sockaddr_un name_bound;
	struct sockaddr_un name_conn;
	struct sockaddr_un name_bound_conn;
	int stream_sock[2];
	int sk_dgram_bound_client;
	int sk_dgram_bound_server;
	int sk_dgram_conn_client;
	int sk_dgram_conn_server;
	int sk_dgram_bound_conn;
	char buf[64];
	int ret;

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, stream_sock) == -1) {
		perror("socketpair");
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
		perror("socket");
		exit(1);
	}

	unlink(SK_NAME_BOUND);
	unlink(SK_NAME_CONN);
	unlink(SK_NAME_BOUND_CONN);

	printf("sk_dgram_bound_client: %d\n"
	       "sk_dgram_bound_server: %d\n"
	       "sk_dgram_conn_client:  %d\n"
	       "sk_dgram_conn_server:  %d\n"
	       "sk_dgram_bound_conn:  %d\n",
		sk_dgram_bound_client,
		sk_dgram_bound_server,
		sk_dgram_conn_client,
		sk_dgram_conn_server,
		sk_dgram_bound_conn);

	name_bound.sun_family = AF_UNIX;
	strcpy(name_bound.sun_path, SK_NAME_BOUND);

	name_conn.sun_family = AF_UNIX;
	strcpy(name_conn.sun_path, SK_NAME_CONN);

	name_bound_conn.sun_family = AF_UNIX;
	strcpy(name_bound_conn.sun_path, SK_NAME_BOUND_CONN);

	ret = bind(sk_dgram_bound_server, &name_bound, sizeof(name_bound));
	if (ret) {
		perror("bind");
		exit(1);
	}

	ret = bind(sk_dgram_conn_server, &name_conn, sizeof(name_conn));
	if (ret) {
		perror("bind");
		exit(1);
	}

	ret = bind(sk_dgram_bound_conn, &name_bound_conn, sizeof(name_bound_conn));
	if (ret) {
		perror("bind");
		exit(1);
	}

	ret = connect(sk_dgram_conn_client, &name_conn, sizeof(name_conn));
	if (ret) {
		perror("connect");
		exit(1);
	}

	ret = connect(sk_dgram_bound_conn, &name_bound_conn, sizeof(name_bound_conn));
	if (ret) {
		perror("connect");
		exit(1);
	}

	/* first packets */

	write(stream_sock[0], SK_DATA_PAIR, sizeof(SK_DATA_PAIR));

	sendto(sk_dgram_bound_client, SK_DATA_BOUND, sizeof(SK_DATA_BOUND), 0,
	       &name_bound, sizeof(name_bound));

	write(sk_dgram_conn_client, SK_DATA_CONN, sizeof(SK_DATA_CONN));

	write(sk_dgram_bound_conn, SK_DATA_BOUND_CONN, sizeof(SK_DATA_BOUND_CONN));

	while (1) {

		read(stream_sock[1], &buf, sizeof(buf));
		printf("stream            : '%s'\n", buf);

		read(sk_dgram_bound_server, &buf, sizeof(buf));
		printf("dgram-bound       : '%s'\n", buf);

		read(sk_dgram_conn_server, &buf, sizeof(buf));
		printf("dgram-conn        : '%s'\n", buf);

		read(sk_dgram_bound_conn, &buf, sizeof(buf));
		printf("dgram-bound-conn  : '%s'\n", buf);

		/*
		 * checkpoint should be done here,
		 * we don't support queued data yet.
		 */
		printf("pause\n");
		sleep(10);

		write(stream_sock[0], SK_DATA_PAIR, sizeof(SK_DATA_PAIR));

		sendto(sk_dgram_bound_client, SK_DATA_BOUND, sizeof(SK_DATA_BOUND), 0,
		       &name_bound, sizeof(name_bound));

		write(sk_dgram_conn_client, SK_DATA_CONN, sizeof(SK_DATA_CONN));

		write(sk_dgram_bound_conn, SK_DATA_BOUND_CONN, sizeof(SK_DATA_BOUND_CONN));
	}

	return 0;
}
