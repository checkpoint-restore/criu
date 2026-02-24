#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#include <semaphore.h>
#include <fcntl.h>

#include "zdtmtst.h"

#define SEM_NAME "/criu-sem-test"
#define SEM_VAL_EXPECTED 2

const char *test_doc = "Check for POSIX semaphores";
const char *test_author = "Sinan Mohd <sinan@sinanmohd.com>";

int main(int argc, char **argv)
{
	sem_t *sem;
	int ret, semval;

	test_init(argc, argv);

	sem = sem_open(SEM_NAME, O_CREAT | O_EXCL, 0600, SEM_VAL_EXPECTED);
	if (sem == SEM_FAILED) {
		pr_perror("sem_open");
		return 1;
	}

	ret = sem_post(sem);
	if (ret == -1) {
		pr_perror("sem_post");
		return 1;
	}
	ret = sem_trywait(sem);
	if (ret == -1) {
		fail("sem_trywait");
		return 1;
	}

	test_daemon();
	test_waitsig();

	ret = sem_post(sem);
	if (ret == -1) {
		fail("sem_post");
		return 1;
	}
	ret = sem_trywait(sem);
	if (ret == -1) {
		fail("sem_trywait");
		return 1;
	}

	ret = sem_getvalue(sem, &semval);
	if (ret == -1) {
		fail("sem_getvalue");
		return 1;
	}
	if (semval != SEM_VAL_EXPECTED) {
		fail("Expected semvalue to be %d, got %d", SEM_VAL_EXPECTED, semval);
		return 1;
	}
	ret = sem_close(sem);
	if (ret == -1) {
		fail("sem_close");
		return 1;
	}
	ret = sem_unlink(SEM_NAME);
	if (ret == -1) {
		fail("sem_unlink");
		return 1;
	}

	pass();
	return 0;
}
