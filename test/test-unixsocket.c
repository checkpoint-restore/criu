#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/un.h>

int main(void)
{
	int sv[2];
	char buf;
	int ret;

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == -1) {
		perror("socketpair");
		exit(1);
	}

	buf = 'a';
	write(sv[0], &buf, 1);
	printf("sent '%c'\n", buf);

	while (1) {
		/* stream */
		read(sv[1], &buf, 1);
		printf("read '%c'\n", buf);

		/*
		 * checkpoint should be done here,
		 * we don't support queued data yet.
		 */
		printf("pause\n");
		sleep(10);

		buf = toupper(buf);
		write(sv[0], &buf, 1);
		printf("sent '%c'\n", buf);
	}

	return 0;
}
