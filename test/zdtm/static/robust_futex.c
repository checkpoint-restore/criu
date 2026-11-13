#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "zdtmtst.h"

const char *test_doc = "Check robust and PI robust mutexes detect their dead owner after c/r";
const char *test_author = "codeafridi <code.afridi@gmail.com>";

struct scenario {
	pthread_mutex_t mtx;
	volatile int owner_locked;
	volatile int waiter_ready;
	volatile int waiter_done;
	volatile int waiter_ret;
	volatile int die;
	pid_t owner;
	pid_t waiter;
};

static struct scenario *sh;

static int wait_flag(volatile int *flag, int ms)
{
	int i;

	for (i = 0; i < ms && !*flag; i++)
		usleep(1000);

	return *flag;
}

static void owner_fn(struct scenario *sc)
{
	if (pthread_mutex_lock(&sc->mtx)) {
		sc->owner_locked = -1;
		_exit(1);
	}

	sc->owner_locked = 1;

	while (!sc->die)
		usleep(1000);

	/* Exit without unlocking, the kernel has to mark the futex as
	 * owner-died through this task's robust list. */
	_exit(0);
}

static void waiter_fn(struct scenario *sc)
{
	int ret;

	sc->waiter_ready = 1;

	ret = pthread_mutex_lock(&sc->mtx);
	sc->waiter_ret = ret;

	if (ret == EOWNERDEAD) {
		if (pthread_mutex_consistent(&sc->mtx))
			sc->waiter_ret = -1;
		else
			pthread_mutex_unlock(&sc->mtx);
	}

	sc->waiter_done = 1;
	_exit(0);
}

static void stop(struct scenario *sc)
{
	if (sc->owner > 0) {
		kill(sc->owner, SIGKILL);
		waitpid(sc->owner, NULL, 0);
		sc->owner = -1;
	}

	if (sc->waiter > 0) {
		kill(sc->waiter, SIGKILL);
		waitpid(sc->waiter, NULL, 0);
		sc->waiter = -1;
	}
}

static int start(struct scenario *sc, int pi)
{
	pthread_mutexattr_t attr;
	pid_t pid;
	int ret = -1;

	sc->owner = -1;
	sc->waiter = -1;

	if (pthread_mutexattr_init(&attr))
		return -1;

	if (pthread_mutexattr_setpshared(&attr, PTHREAD_PROCESS_SHARED) ||
	    pthread_mutexattr_setrobust(&attr, PTHREAD_MUTEX_ROBUST))
		goto out;

	if (pi && pthread_mutexattr_setprotocol(&attr, PTHREAD_PRIO_INHERIT))
		goto out;

	if (pthread_mutex_init(&sc->mtx, &attr))
		goto out;

	pid = fork();
	if (pid < 0)
		goto out;

	if (!pid)
		owner_fn(sc);

	sc->owner = pid;

	/* The owner has to hold the lock before the waiter starts, otherwise
	 * they race for it and the wrong process becomes the owner. */
	if (!wait_flag(&sc->owner_locked, 5000) || sc->owner_locked != 1) {
		stop(sc);
		goto out;
	}

	pid = fork();
	if (pid < 0) {
		stop(sc);
		goto out;
	}

	if (!pid)
		waiter_fn(sc);

	sc->waiter = pid;

	ret = 0;
out:
	pthread_mutexattr_destroy(&attr);
	return ret;
}

static int check(struct scenario *sc, const char *name)
{
	struct timespec ts;
	int status, ret;

	sc->die = 1;

	if (waitpid(sc->owner, &status, 0) != sc->owner) {
		fail("%s: can't wait for the owner", name);
		goto err;
	}
	sc->owner = -1;

	if (!WIFEXITED(status) || WEXITSTATUS(status)) {
		fail("%s: owner exited abnormally", name);
		goto err;
	}

	if (!wait_flag(&sc->waiter_done, 5000)) {
		fail("%s: waiter didn't wake up, dead owner was not detected", name);
		goto err;
	}

	if (waitpid(sc->waiter, &status, 0) != sc->waiter) {
		fail("%s: can't wait for the waiter", name);
		goto err;
	}
	sc->waiter = -1;

	if (!WIFEXITED(status) || WEXITSTATUS(status)) {
		fail("%s: waiter exited abnormally", name);
		goto err;
	}

	if (sc->waiter_ret != EOWNERDEAD) {
		if (sc->waiter_ret == -1)
			fail("%s: waiter can't make the mutex consistent", name);
		else
			fail("%s: waiter got %d instead of EOWNERDEAD", name, sc->waiter_ret);
		return -1;
	}

	/* The waiter made the mutex consistent, so we can take it now. */
	clock_gettime(CLOCK_REALTIME, &ts);
	ts.tv_sec += 5;

	ret = pthread_mutex_timedlock(&sc->mtx, &ts);
	if (ret) {
		fail("%s: can't lock the recovered mutex (%d)", name, ret);
		return -1;
	}

	pthread_mutex_unlock(&sc->mtx);
	return 0;
err:
	stop(sc);
	return -1;
}

int main(int argc, char **argv)
{
	struct scenario *normal, *pi;

	test_init(argc, argv);

	sh = mmap(NULL, 2 * sizeof(*sh), PROT_READ | PROT_WRITE,
		  MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (sh == MAP_FAILED) {
		pr_perror("mmap");
		return 1;
	}

	normal = &sh[0];
	pi = &sh[1];

	if (start(normal, 0)) {
		fail("Can't start the test processes");
		return 1;
	}

	if (start(pi, 1)) {
		stop(normal);
		fail("Can't start the PI test processes");
		return 1;
	}

	if (!wait_flag(&normal->waiter_ready, 5000) ||
	    !wait_flag(&pi->waiter_ready, 5000)) {
		fail("Waiter didn't start");
		goto out;
	}

	/* Give the waiters time to block in the futex before c/r. */
	usleep(100000);

	test_daemon();
	test_waitsig();

	if (check(normal, "robust"))
		goto out;

	if (check(pi, "PI robust"))
		goto out;

	pass();
out:
	stop(normal);
	stop(pi);
	return 0;
}
