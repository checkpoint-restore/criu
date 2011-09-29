/*
 * A simple testee program with threads
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <pthread.h>


static pthread_mutex_t mtx = PTHREAD_MUTEX_INITIALIZER;
static int counter;

static void *f1(void *arg)
{
	void *map_unreadable = mmap(NULL, 1024, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	(void)map_unreadable;

	while (1) {
		pthread_mutex_lock(&mtx);

		counter++;
		/* printf("Counter value: %d\n", counter); */

		pthread_mutex_unlock(&mtx);
		sleep(2);
	}

	return NULL;
}

static void *f2(void *arg)
{
	void *map_unreadable = mmap(NULL, 1024, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	(void)map_unreadable;

	while (1) {
		pthread_mutex_lock(&mtx);

		counter++;
		/* printf("Counter value: %d\n", counter); */

		pthread_mutex_unlock(&mtx);
		sleep(3);
	}

	return NULL;
}

int main(int argc, char *argv[])
{
	pthread_t th1, th2;
	int rc1, rc2;

	printf("%s pid %d\n", argv[0], getpid());

	rc1 = pthread_create(&th1, NULL, &f1, NULL);
	rc2 = pthread_create(&th2, NULL, &f2, NULL);

	if (rc1 | rc2)
		exit(1);

	pthread_join(th1, NULL);
	pthread_join(th2, NULL);

	exit(0);
}
