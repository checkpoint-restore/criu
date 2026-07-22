#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include "zdtmtst.h"

const char *test_doc = "Test robust mutex restore through CRIU ghost files.";
const char *test_author = "Radostin Stoyanov <rstoyanov@fedoraproject.org>";

struct shm_state {
	pthread_mutex_t mutex;
	volatile int worker_started;
	volatile int worker_done;
	volatile int worker_lock_ret;
};

#define SHM_NAME_FMT "/zdtm_shmem_tmpfs_robust_mutex_unlinked_%d"

static void *worker_fn(void *arg)
{
	struct shm_state *st = arg;

	st->worker_started = 1;
	st->worker_lock_ret = pthread_mutex_lock(&st->mutex);
	st->worker_done = 1;

	return NULL;
}

int main(int argc, char **argv)
{
	char shm_name[64];
	pthread_mutexattr_t attr;
	pthread_t worker;
	struct shm_state *st;
	int fd;

	test_init(argc, argv);

	snprintf(shm_name, sizeof(shm_name), SHM_NAME_FMT, getpid());

	fd = shm_open(shm_name, O_CREAT | O_EXCL | O_RDWR, 0600);
	if (fd < 0) {
		pr_perror("shm_open");
		return 1;
	}

	if (ftruncate(fd, sizeof(*st))) {
		pr_perror("ftruncate");
		return 1;
	}

	st = mmap(NULL, sizeof(*st), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (st == MAP_FAILED) {
		pr_perror("mmap");
		return 1;
	}
	close(fd);

	/* Unlink now: the mapping stays live, but the backing tmpfs file is
	 * gone from the filesystem, forcing restore through CRIU's ghost-file
	 * remap path instead of a plain path reopen.
	 */
	if (shm_unlink(shm_name)) {
		pr_perror("shm_unlink");
		return 1;
	}

	if (pthread_mutexattr_init(&attr) || pthread_mutexattr_setpshared(&attr, PTHREAD_PROCESS_SHARED) ||
	    pthread_mutexattr_setrobust(&attr, PTHREAD_MUTEX_ROBUST) || pthread_mutex_init(&st->mutex, &attr)) {
		pr_perror("Can't init robust process-shared mutex");
		return 1;
	}

	if (pthread_mutex_lock(&st->mutex)) {
		pr_perror("Can't take initial lock");
		return 1;
	}

	st->worker_started = 0;
	st->worker_done = 0;

	if (pthread_create(&worker, NULL, worker_fn, st)) {
		pr_perror("Can't create worker thread");
		return 1;
	}

	while (!st->worker_started)
		usleep(1000);
	/* Give the worker a moment to actually enter the futex wait. */
	usleep(100000);

	test_daemon();
	test_waitsig();

	{
		int ret = pthread_mutex_unlock(&st->mutex);

		if (ret) {
			fail("Can't unlock mutex after restore: %s", strerror(ret));
			goto out;
		}
	}

	while (!st->worker_done)
		usleep(1000);

	pthread_join(worker, NULL);

	if (st->worker_lock_ret != 0) {
		fail("worker woke with %s instead of success", strerror(st->worker_lock_ret));
		goto out;
	}

	pass();
out:
	munmap(st, sizeof(*st));
	return 0;
}
