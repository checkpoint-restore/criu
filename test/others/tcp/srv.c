#include <sys/socket.h>
#include <linux/types.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <signal.h>

static int serve_new_conn(int sk)
{
	int rd, wr;
	char buf[1024];

	printf("New connection\n");

	while (1) {
		rd = read(sk, buf, sizeof(buf));
		if (!rd)
			break;

		if (rd < 0) {
			perror("Can't read socket");
			return 1;
		}

		wr = 0;
		while (wr < rd) {
			int w;

			w = write(sk, buf + wr, rd - wr);
			if (w <= 0) {
				perror("Can't write socket");
				return 1;
			}

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

	if (argc < 2) {
		printf("Need port\n");
		return -1;
	}

	/*
	 * Let kids die themselves
	 */

	signal(SIGCHLD, SIG_IGN);

	sk = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sk < 0) {
		perror("Can't create socket");
		return -1;
	}

	port = atoi(argv[1]);
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	addr.sin_port = htons(port);

	printf("Binding to port %d\n", port);

	ret = bind(sk, (struct sockaddr *)&addr, sizeof(addr));
	if (ret < 0) {
		perror("Can't bind socket");
		return -1;
	}

	ret = listen(sk, 16);
	if (ret < 0) {
		perror("Can't put sock to listen");
		return -1;
	}

	printf("Waiting for connections\n");
	while (1) {
		int ask, pid;

		ask = accept(sk, NULL, NULL);
		if (ask < 0) {
			perror("Can't accept new conn");
			return -1;
		}

		pid = fork();
		if (pid < 0) {
			perror("Can't fork");
			return -1;
		}

		if (pid > 0)
			close(ask);
		else {
			close(sk);
			ret = serve_new_conn(ask);
			exit(ret);
		}
	}
}
