#include <errno.h>
#include <pthread.h>
#include <sys/personality.h>

#include "zdtmtst.h"

const char *test_doc = "Check that per-thread personality is preserved across C/R";
const char *test_author = "srinivasr <sriniv4sreddy@gmail.com>";

/*
 * Personality is a u32. Reading it into an int makes any value with bit 31
 * set appear negative. In glibc, personality() returns the previous value as
 * int, which is negative when bit 31 was set, while errors return -1 with
 * errno set. Use set_personality() to check errno properly.
 */
#define PERSONA_QUERY 0xffffffffu

#ifndef ADDR_COMPAT_LAYOUT
#define ADDR_COMPAT_LAYOUT 0x00200000
#endif

static unsigned int t1_after = ~0u;
static unsigned int t2_after = ~0u;
static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
static int children_ready = 0;
static int t1_status = 0;
static int t2_status = 0;
static int restored = 0;

static int set_personality(unsigned int p)
{
	errno = 0;
	if (personality(p) == -1 && errno != 0)
		return -1;
	return 0;
}

static unsigned int get_personality(void)
{
	int p;

	errno = 0;
	p = personality(PERSONA_QUERY);
	if (p == -1 && errno != 0) {
		fail("can't query personality");
		return ~0u;
	}
	return (unsigned int)p;
}

/* Worker 1: clears ADDR_COMPAT_LAYOUT which the leader has set. */
static void *thread_fn_clear(void *arg)
{
	unsigned int p = get_personality();
	int err = 0;

	(void)arg;

	if (p == ~0u) {
		err = -1;
	} else if (set_personality(p & ~ADDR_COMPAT_LAYOUT)) {
		fail("thread 1 can't clear ADDR_COMPAT_LAYOUT");
		err = -1;
	}

	pthread_mutex_lock(&mutex);
	t1_status = err;
	children_ready++;
	pthread_cond_broadcast(&cond);

	if (err) {
		pthread_mutex_unlock(&mutex);
		return NULL;
	}

	while (!restored)
		pthread_cond_wait(&cond, &mutex);
	pthread_mutex_unlock(&mutex);

	t1_after = get_personality();
	return NULL;
}

/* Worker 2: sets ADDR_NO_RANDOMIZE which the leader has clear. */
static void *thread_fn_set(void *arg)
{
	unsigned int p = get_personality();
	int err = 0;

	(void)arg;

	if (p == ~0u) {
		err = -1;
	} else if (set_personality(p | ADDR_NO_RANDOMIZE)) {
		fail("thread 2 can't set ADDR_NO_RANDOMIZE");
		err = -1;
	}

	pthread_mutex_lock(&mutex);
	t2_status = err;
	children_ready++;
	pthread_cond_broadcast(&cond);

	if (err) {
		pthread_mutex_unlock(&mutex);
		return NULL;
	}

	while (!restored)
		pthread_cond_wait(&cond, &mutex);
	pthread_mutex_unlock(&mutex);

	t2_after = get_personality();
	return NULL;
}

int main(int argc, char **argv)
{
	pthread_t t1, t2;
	unsigned int persona, after;
	int ret;

	test_init(argc, argv);

	persona = get_personality();
	if (persona == ~0u)
		return 1;

	/*
	 * The leader sets ADDR_COMPAT_LAYOUT and ensures ADDR_NO_RANDOMIZE is clear.
	 * Set it before threads are created so thread placement is deterministic.
	 */
	persona = (persona | ADDR_COMPAT_LAYOUT) & ~ADDR_NO_RANDOMIZE;
	if (set_personality(persona)) {
		fail("can't set leader personality");
		return 1;
	}
	persona = get_personality();
	if (persona == ~0u)
		return 1;

	ret = pthread_create(&t1, NULL, thread_fn_clear, NULL);
	if (ret) {
		fail("can't create thread 1");
		return 1;
	}

	ret = pthread_create(&t2, NULL, thread_fn_set, NULL);
	if (ret) {
		fail("can't create thread 2");
		return 1;
	}

	pthread_mutex_lock(&mutex);
	while (children_ready < 2)
		pthread_cond_wait(&cond, &mutex);

	if (t1_status != 0 || t2_status != 0) {
		pthread_mutex_unlock(&mutex);
		fail("worker thread initialization failed");
		return 1;
	}
	pthread_mutex_unlock(&mutex);

	test_daemon();
	test_waitsig();

	pthread_mutex_lock(&mutex);
	restored = 1;
	pthread_cond_broadcast(&cond);
	pthread_mutex_unlock(&mutex);

	after = get_personality();
	if (after == ~0u)
		return 1;

	ret = pthread_join(t1, NULL);
	if (ret) {
		fail("can't join thread 1");
		return 1;
	}

	ret = pthread_join(t2, NULL);
	if (ret) {
		fail("can't join thread 2");
		return 1;
	}

	/* Compare exact full values for leader and both workers. */
	if (after != persona) {
		fail("main personality changed: before=0x%08x after=0x%08x", persona, after);
		return 1;
	}

	if (t1_after == ~0u) {
		fail("thread 1 never reported its restored personality");
		return 1;
	}

	if (t1_after != (persona & ~ADDR_COMPAT_LAYOUT)) {
		fail("thread 1 personality wrong: want=0x%08x got=0x%08x",
		     persona & ~ADDR_COMPAT_LAYOUT, t1_after);
		return 1;
	}

	if (t2_after == ~0u) {
		fail("thread 2 never reported its restored personality");
		return 1;
	}

	if (t2_after != (persona | ADDR_NO_RANDOMIZE)) {
		fail("thread 2 personality wrong: want=0x%08x got=0x%08x",
		     persona | ADDR_NO_RANDOMIZE, t2_after);
		return 1;
	}

	pass();
	return 0;
}
