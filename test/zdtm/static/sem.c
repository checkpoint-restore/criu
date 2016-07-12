#define _GNU_SOURCE
#include <sched.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ipc.h>
#include <sys/sem.h>
#include <signal.h>
#include <errno.h>

#include "zdtmtst.h"

const char *test_doc="Tests IPC semaphores migrates fine";
const char *test_author="Stanislav Kinsbursky <skinsbursky@parallels.com>";

static int sem_test(int id,
		    struct sembuf *lock, struct sembuf *unlock,
		    int lock_ops, int unlock_ops)
{
	if (semop(id, lock, lock_ops) == -1) {
		fail("Failed to lock semaphore");
		return -errno;
	}
	if (semop(id, unlock, unlock_ops) == -1) {
		fail("Failed to unlock semaphore");
		return -errno;
	}
	return 0;
}

#define NSEMS 10

static int check_sem_by_key(int key, int num)
{
	int id;
	struct sembuf lock[2] = {
		{
		.sem_num = num,
		.sem_op = 0,
		.sem_flg = 0,
		},
		{
		.sem_num = num,
		.sem_op = 1,
		.sem_flg = 0,
		},
	};
	struct sembuf unlock[1] = {
		{
		.sem_num = num,
		.sem_op = -1,
		.sem_flg = 0,
		}
	};
	int val;

	id = semget(key, NSEMS, 0777);
	if (id  == -1) {
		fail("Can't get sem");
		return -errno;
	}

	val = semctl(id, num, GETVAL);
	if (val < 0) {
		fail("Failed to get sem value");
		return -errno;
	}

	return sem_test(id, lock, unlock,
			sizeof(lock)/sizeof(struct sembuf),
			sizeof(unlock)/sizeof(struct sembuf));
}

static int check_sem_by_id(int id, int num, int val)
{
	int curr;
	struct sembuf lock[] = {
		{
		.sem_num = num,
		.sem_op = val,
		.sem_flg = 0,
		},
	};
	struct sembuf unlock[] = {
		{
		.sem_num = num,
		.sem_op = - val * 2,
		.sem_flg = 0,
		}
	};

	curr = semctl(id, num, GETVAL);
	if (curr < 0) {
		fail("Failed to get sem value");
		return -errno;
	}
	if (curr != val) {
		fail("Sem has wrong value: %d instead of %d\n", curr, val);
		return -EFAULT;
	}
	return sem_test(id, lock, unlock,
			sizeof(lock)/sizeof(struct sembuf),
			sizeof(unlock)/sizeof(struct sembuf));
}

int main(int argc, char **argv)
{
	int id, key;
	int i;
	int val[NSEMS];
	int ret, fail_count = 0;

	test_init(argc, argv);

	key = ftok(argv[0], 89063453);
	if (key == -1) {
		pr_perror("Can't make key");
		return -1;
	}

	id = semget(key, NSEMS, 0777 | IPC_CREAT | IPC_EXCL);
	if (id  == -1) {
		fail_count++;
		pr_perror("Can't get sem array");
		goto out;
	}

	for (i = 0; i < NSEMS; i++) {
		val[i] = lrand48() & 0x7;

		if (semctl(id, i, SETVAL, val[i]) == -1) {
			fail_count++;
			pr_perror("Can't init sem %d", i);
			goto out_destroy;
		}
	}

	test_daemon();
	test_waitsig();

	for (i = 0; i < NSEMS; i++) {
		ret = check_sem_by_id(id, i, val[i]);
		if (ret < 0) {
			fail_count++;
			fail("Check sem %d by id failed", i);
			goto out_destroy;
		}

		if (check_sem_by_key(key, i) < 0) {
			fail("Check sem %d by key failed", i);
			fail_count++;
			goto out_destroy;
		}

		val[i] = semctl(id, 0, GETVAL);
		if (val[i] < 0) {
			fail("Failed to get sem %d value", i);
			fail_count++;
			goto out_destroy;
		}
		if (val[i] != 0) {
			fail("Non-zero sem %d value: %d", i, val[i]);
			fail_count++;
		}
	}

out_destroy:
	ret = semctl(id, 0, IPC_RMID);
	if (ret < 0) {
		fail("Destroy sem array failed");
		fail_count++;
	}
out:
	if (fail_count == 0)
		pass();
	return fail_count;
}
