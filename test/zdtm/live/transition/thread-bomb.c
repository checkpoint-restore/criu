#include <pthread.h>
#include <unistd.h>
#include <linux/unistd.h>
#include <syscall.h>
#include <fcntl.h>
#include <errno.h>

#include "zdtmtst.h"

static int p[2];
static char buf[100]; /* the size is equal to the limit of threads */

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
	if (pipe(p))
		return 1;
	fcntl(p[0], F_SETFL, O_NONBLOCK);

	if (write(p[1], buf, sizeof(buf)) != sizeof(buf))
		return 1;

	test_init(argc, argv);
	test_daemon();

	thread_fn(NULL);

	pass();

	return 0;
}
