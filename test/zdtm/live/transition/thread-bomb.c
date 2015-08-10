#include <pthread.h>
#include <unistd.h>
#include <linux/unistd.h>
#include <syscall.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>

#include "zdtmtst.h"

static int p[2];
static char *buf;
static int buf_size = 1024;

#define exit_group(code)	\
	syscall(__NR_exit_group, code)

static void *thread_fn(void *arg)
{
	pthread_t t;
	char c = 0;
	int ret;

	while (test_go()) {
		ret = read(p[0], &c, 1);
		if (ret == -1 && errno == EAGAIN)
			return NULL;
		if (ret != 1)
			goto err;
		if (pthread_create(&t, NULL, thread_fn, NULL))
			goto err;
		pthread_join(t, NULL);
		if (write(p[1], &c, 1) != 1)
			goto err;
	}

	return NULL;
err:
	exit_group(1);
	return NULL;
}

int main(int argc, char **argv)
{
	char *val;

	val = getenv("ZDTM_THREAD_BOMB");
	if (val)
		buf_size = atoi(val);
	test_msg("%d\n", buf_size);
	buf = malloc(buf_size);
	if (!buf)
		return 1;

	if (pipe(p))
		return 1;
	fcntl(p[0], F_SETFL, O_NONBLOCK);

	if (write(p[1], buf, buf_size) != buf_size)
		return 1;

	test_init(argc, argv);
	test_daemon();

	thread_fn(NULL);

	pass();

	return 0;
}
