#include <pthread.h>
#include <sys/personality.h>

#include "zdtmtst.h"

const char *test_doc = "Check that the ADDR_NO_RANDOMIZE personality bit is preserved across C/R";
const char *test_author = "srinivasr <sriniv4sreddy@gmail.com>";

static volatile int child_after = -1;
static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
static int restored = 0;

static int check_personality(void)
{
	return personality(0xffffffff);
}

static void *thread_fn(void *arg)
{
	pthread_mutex_lock(&mutex);
	while (!restored)
		pthread_cond_wait(&cond, &mutex);
	pthread_mutex_unlock(&mutex);

	child_after = check_personality();
	return NULL;
}

int main(int argc, char **argv)
{
	pthread_t thread;
	int persona, after;
	int ret;

	test_init(argc, argv);

	persona = personality(0xffffffff);
	if (persona < 0) {
		fail("can't read personality");
		return 1;
	}

	ret = personality(persona | ADDR_NO_RANDOMIZE);
	if (ret < 0) {
		fail("can't set ADDR_NO_RANDOMIZE");
		return 1;
	}

	ret = pthread_create(&thread, NULL, thread_fn, NULL);
	if (ret) {
		fail("can't create thread");
		return 1;
	}

	test_daemon();
	test_waitsig();

	pthread_mutex_lock(&mutex);
	restored = 1;
	pthread_cond_signal(&cond);
	pthread_mutex_unlock(&mutex);

	after = check_personality();
	if (after < 0) {
		fail("can't read restored personality");
		return 1;
	}

	ret = pthread_join(thread, NULL);
	if (ret) {
		fail("can't join thread");
		return 1;
	}

	if (child_after < 0) {
		fail("can't read child restored personality");
		return 1;
	}

	if (!(after & ADDR_NO_RANDOMIZE)) {
		fail("main personality lost: before=0x%x after=0x%x", persona | ADDR_NO_RANDOMIZE, after);
		return 1;
	}

	if (!(child_after & ADDR_NO_RANDOMIZE)) {
		fail("child personality lost: before=0x%x after=0x%x", persona | ADDR_NO_RANDOMIZE, child_after);
		return 1;
	}

	pass();
	return 0;
}
