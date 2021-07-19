#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <signal.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <linux/un.h>
#include <fcntl.h>

#include <syslog.h>

#define SK_NAME "/tmp/criu.unix.callback.test"

#define SK_NR 2
struct {
	int id;
	int sk;
	int val;
} sks[SK_NR];

static int create_sock(int i)
{
	int ret, id, sk, val = time(NULL) + i * 314;
	char buf[4096];
	struct sockaddr_un addr;
	socklen_t addr_len;

	id = getpid() * 10 + i;
	sk = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (sk < 0)
		return -1;

	addr.sun_family = AF_UNIX;
	addr_len = snprintf(addr.sun_path, UNIX_PATH_MAX, "%s%d", SK_NAME, id);
	addr_len += sizeof(addr.sun_family);

	if (bind(sk, (struct sockaddr *)&addr, addr_len) < 0) {
		perror("bind");
		return 1;
	}

	addr.sun_family = AF_UNIX;
	addr_len = snprintf(addr.sun_path, UNIX_PATH_MAX, SK_NAME);
	addr_len += sizeof(addr.sun_family);

	if (connect(sk, (struct sockaddr *)&addr, addr_len) < 0) {
		perror("connect");
		return 1;
	}

	printf("init %d\n", val);
	ret = sprintf(buf, "t%d", val);
	if (send(sk, buf, ret, 0) < 0) {
		perror("send");
		return -1;
	}

	sks[i].sk = sk;
	sks[i].val = val;

	return 0;
}

static int check_sock(int i)
{
	int sk = sks[i].sk, val = sks[i].val;
	char buf[4096];

	if (send(sk, "r", 1, 0) < 0) {
		perror("send(\"r\")");
		return -1;
	}

	if (recv(sk, buf, sizeof(buf), 0) <= 0) {
		perror("recv");
		return -1;
	}

	printf("%s - %d\n", buf, val);
	if (atoi(buf) != val)
		return -1;

	return 0;
}

int main(void)
{
	int i, fd;
	sigset_t set;
	int sig;

	for (i = 0; i < SK_NR; i++)
		if (create_sock(i))
			return -1;

	fd = open("pid", O_WRONLY | O_CREAT, 0666);
	if (fd < 0)
		return 1;
	dprintf(fd, "%d\n", getpid());
	close(fd);

	openlog("test", LOG_NDELAY, LOG_USER);

	sigemptyset(&set);
	sigaddset(&set, SIGTERM);
	sigprocmask(SIG_BLOCK, &set, NULL);
	sigwait(&set, &sig);

	syslog(LOG_CRIT, "test message");

	for (i = 0; i < SK_NR; i++)
		if (check_sock(i))
			return -1;

	printf("PASS\n");
	return 0;
}
