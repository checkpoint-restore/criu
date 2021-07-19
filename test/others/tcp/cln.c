#include <sys/socket.h>
#include <linux/types.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <signal.h>

#define BUF_SIZE (1024)

static char rbuf[BUF_SIZE];
static char buf[BUF_SIZE];

static int check_buf(int sk, char *buf, int count)
{
	int rd, i;

	printf("Checking for %d bytes\n", count);

	rd = 0;
	while (rd < count) {
		int r;

		r = read(sk, rbuf + rd, count - rd);
		if (r == 0) {
			printf("Unexpected EOF\n");
			return 1;
		}

		if (r < 0) {
			perror("Can't read buf");
			return 1;
		}

		rd += r;
	}

	for (i = 0; i < count; i++)
		if (buf[i] != rbuf[i]) {
			printf("Mismatch on %d byte %d != %d\n", i, (int)buf[i], (int)rbuf[i]);
			return 1;
		}

	return 0;
}

static int serve_new_conn(int in_fd, int sk)
{
	printf("New connection\n");

	while (1) {
		int rd, wr;

		rd = read(in_fd, buf, sizeof(buf));
		if (rd == 0)
			break;
		if (rd < 0) {
			perror("Can't read from infd");
			return 1;
		}

		printf("Read %d bytes, sending to sock\n", rd);

		wr = 0;
		while (wr < rd) {
			int w;

			w = write(sk, buf + wr, rd - wr);
			if (w <= 0) {
				perror("Can't write to socket");
				return 1;
			}

			if (check_buf(sk, buf + wr, w))
				return 1;

			wr += w;
		}
	}

	printf("Done\n");
	return 0;
}

int main(int argc, char **argv)
{
	int sk, port, ret;
	struct sockaddr_in addr;

	if (argc < 3) {
		printf("Need addr, port and iters\n");
		return -1;
	}

	sk = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sk < 0) {
		perror("Can't create socket");
		return -1;
	}

	port = atoi(argv[2]);
	printf("Connecting to %s:%d\n", argv[1], port);
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	ret = inet_aton(argv[1], &addr.sin_addr);
	if (ret < 0) {
		perror("Can't convert addr");
		return -1;
	}
	addr.sin_port = htons(port);

	ret = connect(sk, (struct sockaddr *)&addr, sizeof(addr));
	if (ret < 0) {
		perror("Can't connect");
		return -1;
	}

	return serve_new_conn(0, sk);
}
