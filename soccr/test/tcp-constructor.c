#include <unistd.h>
#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/socket.h>
#include <netinet/tcp.h>
#include <string.h>
#include <getopt.h>
#include <stdlib.h>

#include "soccr/soccr.h"

#define pr_perror(fmt, ...)                                                                  \
	({                                                                                   \
		fprintf(stderr, "%s:%d: " fmt " : %m\n", __func__, __LINE__, ##__VA_ARGS__); \
		1;                                                                           \
	})

struct tcp {
	char *addr;
	uint32_t port;
	uint32_t seq;
	uint16_t mss_clamp;
	uint16_t wscale;
};

static void usage(void)
{
	printf("Usage: --addr ADDR -port PORT --seq SEQ --next --addr ADDR -port PORT --seq SEQ -- CMD ...\n"
	       "\t Describe a source side of a connection, then set the --next option\n"
	       "\t and describe a destination side.\n"
	       "\t --reverse - swap source and destination sides\n"
	       "\t The idea is that the same command line is execute on both sides,\n"
	       "\t but the --reverse is added to one of them.\n"
	       "\n"
	       "\t CMD ... - a user command to handle a socket, which is the descriptor 3.\n"
	       "\n"
	       "\t It prints the \"start\" on stdout when a socket is created and\n"
	       "\t resumes it when you write \"start\" to stdin.\n");
}

int main(int argc, char **argv)
{
	static const char short_opts[] = "";
	static struct option long_opts[] = {
		{ "addr", required_argument, 0, 'a' }, { "port", required_argument, 0, 'p' },
		{ "seq", required_argument, 0, 's' },  { "next", no_argument, 0, 'n' },
		{ "reverse", no_argument, 0, 'r' },    {},
	};
	struct tcp tcp[2] = { { "127.0.0.1", 12345, 5000000, 1460, 7 }, { "127.0.0.1", 54321, 6000000, 1460, 7 } };

	int sk, yes = 1, val, idx, opt, i, src = 0, dst = 1;
	union libsoccr_addr src_addr, dst_addr;
	struct libsoccr_sk_data data = {};
	struct libsoccr_sk *so;
	char buf[1024];

	i = 0;
	while (1) {
		idx = -1;
		opt = getopt_long(argc, argv, short_opts, long_opts, &idx);
		if (opt == -1)
			break;

		switch (opt) {
		case 'a':
			tcp[i].addr = optarg;
			break;
		case 'p':
			tcp[i].port = atol(optarg);
			break;
		case 's':
			tcp[i].seq = atol(optarg);
			break;
		case 'n':
			i++;
			if (i > 1)
				return pr_perror("--next is used twice or more");
			break;
		case 'r':
			src = 1;
			dst = 0;
			break;
		default:
			usage();
			return 3;
		}
	}
	if (i != 1)
		return pr_perror("--next is required");

	if (optind == argc) {
		usage();
		return 1;
	}

	for (i = 0; i < 2; i++)
		fprintf(stderr, "%s:%d:%d\n", tcp[i].addr, tcp[i].port, tcp[i].seq);

	data.state = TCP_ESTABLISHED;
	data.inq_seq = tcp[dst].seq;
	data.outq_seq = tcp[src].seq;

	sk = socket(AF_INET, SOCK_STREAM, 0);
	if (sk < 0)
		return pr_perror("socket");

	so = libsoccr_pause(sk);

	if (setsockopt(sk, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) == -1)
		return pr_perror("setsockopt");

	src_addr.v4.sin_family = AF_INET;
	src_addr.v4.sin_port = htons(tcp[src].port);
	if (inet_pton(AF_INET, tcp[src].addr, &src_addr.v4.sin_addr) != 1)
		return pr_perror("inet_pton");

	dst_addr.v4.sin_family = AF_INET;
	dst_addr.v4.sin_port = htons(tcp[dst].port);
	if (inet_pton(AF_INET, tcp[dst].addr, &(dst_addr.v4.sin_addr)) != 1)
		return pr_perror("inet_pton");

	libsoccr_set_addr(so, 1, &src_addr, 0);
	libsoccr_set_addr(so, 0, &dst_addr, 0);

	data.snd_wscale = tcp[src].wscale;
	data.rcv_wscale = tcp[dst].wscale;
	data.mss_clamp = tcp[src].mss_clamp;

	data.opt_mask = TCPI_OPT_WSCALE | TCPOPT_MAXSEG;

	if (libsoccr_restore(so, &data, sizeof(data)))
		return 1;

	/* Let's go */
	if (write(STDOUT_FILENO, "start", 5) != 5)
		return pr_perror("write");
	if (read(STDIN_FILENO, buf, 5) != 5)
		return pr_perror("read");

	val = 0;
	if (setsockopt(sk, SOL_TCP, TCP_REPAIR, &val, sizeof(val)))
		return pr_perror("TCP_REPAIR");

	execv(argv[optind], argv + optind);

	return pr_perror("Unable to exec %s", argv[optind]);
}
