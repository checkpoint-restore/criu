#define _GNU_SOURCE
#include <stdlib.h>
#include <syscall.h>
#include <pthread.h>

#include "zdtmtst.h"

const char *test_doc    = "Check that shared FS is migrated properly";
const char *test_author = "Stanislav Kinsburskiy <skinsbursky@virtuozzo.com>";

enum kcmp_type {
	KCMP_FILE,
	KCMP_VM,
	KCMP_FILES,
	KCMP_FS,
	KCMP_SIGHAND,
	KCMP_IO,
	KCMP_SYSVSEM,

	KCMP_TYPES,
};

static int kcmp(int type, pid_t pid1, pid_t pid2, unsigned long idx1, unsigned long idx2)
{
	int ret;

	ret = syscall(SYS_kcmp, pid1, pid2, type, idx1, idx2);

	switch (ret) {
		case 0:
			break;
		case 1:
		case 2:
			test_msg("FS for pids %d and %d doesn't match: %d\n", pid1, pid2, ret);
			break;
		case -1:
			pr_err("kcmp (type: %d, pid1: %d, pid2: %d, "
					"idx1: %ld, idx2: %ld) failed: %d\n",
					type, pid1, pid2, idx1, idx2, errno);
			break;
		default:
			pr_err("kcmp (type: %d, pid1: %d, pid2: %d, "
					"idx1: %ld, idx2: %ld) returned %d\n",
					type, pid1, pid2, idx1, idx2, ret);
			break;
	}
	return ret;
}

#define gettid(code)        \
	        syscall(__NR_gettid)

static pthread_mutex_t init_lock;
static pthread_mutex_t exit_lock;

static void *thread_func(void *tid2)
{
	*(int *)tid2 = gettid();

	pthread_mutex_unlock(&init_lock);
	pthread_mutex_lock(&exit_lock);

	return NULL;
}

int main(int argc, char **argv)
{
	pid_t tid;
	int ret;
	pthread_t th;

        test_init(argc, argv);

	pthread_mutex_init(&init_lock, NULL);
	pthread_mutex_lock(&init_lock);
	pthread_mutex_init(&exit_lock, NULL);
	pthread_mutex_lock(&exit_lock);

	if (pthread_create(&th, NULL, thread_func, &tid)) {
		fail("Can't pthread_create");
		return 1;
	}

	pthread_mutex_lock(&init_lock);

	ret = kcmp(KCMP_FS, gettid(), tid, 0, 0);
	if (ret)
		exit(1);

	test_daemon();
	test_waitsig();

	ret = kcmp(KCMP_FS, gettid(), tid, 0, 0);
	if (ret) {
		fail();
		exit(1);
	}

	pthread_mutex_unlock(&exit_lock);
	pthread_join(th, NULL);

	pass();

	return 0;
}
