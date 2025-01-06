/*
 * A simple testee program with threads
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <pthread.h>

#include "zdtmtst.h"

const char *test_doc = "Create a thread with a dead leader\n";
const char *test_author = "Andrew Vagin <avagin@openvz.org";

static void *thread_func(void *args)
{
	test_waitsig();
	pass();
	exit(0);
}

int main(int argc, char *argv[])
{
	pthread_t th1;
	int ret;

	test_init(argc, argv);

	ret = pthread_create(&th1, NULL, &thread_func, NULL);

	if (ret) {
		fail("Can't pthread_create");
		exit(1);
	}

	test_daemon();

	pthread_exit(NULL);
	return 0;
}
