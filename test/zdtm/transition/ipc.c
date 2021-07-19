#include <sched.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/sem.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <signal.h>
#include <errno.h>

#include "zdtmtst.h"

const char *test_doc = "Tests ipc sems and shmems migrate fine";
const char *test_author = "Pavel Emelianov <xemul@parallels.com>";

static struct sembuf unlock = {
	.sem_op = 1,
	.sem_num = 0,
	.sem_flg = 0,
};

static struct sembuf lock = {
	.sem_op = -1,
	.sem_num = 0,
	.sem_flg = 0,
};

#define DEF_MEM_SIZE (40960)
unsigned int shmem_size = DEF_MEM_SIZE;
TEST_OPTION(shmem_size, uint, "Size of shared memory segment", 0);

#define INIT_CRC (~0)

#define POISON 0xac
static inline void poison_area(int *mem)
{
	memset(mem, POISON, shmem_size);
}

static int child(key_t key)
{
	int sem, shm, ret, res = 0;
	uint8_t *mem;
	uint32_t crc;

	sem = semget(key, 1, 0777);
	if (sem == -1)
		return -1;
	shm = shmget(key, shmem_size, 0777);
	if (shm == -1)
		return -2;
	mem = shmat(shm, NULL, 0);
	if (mem == (uint8_t *)-1)
		return -3;

	while (test_go()) {
		ret = semop(sem, &lock, 1);
		if (ret) {
			if (errno == EINTR)
				continue;
			fail("Error in semop lock");
			res = errno;
			break;
		}
		crc = INIT_CRC;
		datagen(mem, shmem_size, &crc);
		while ((ret = semop(sem, &unlock, 1)) && (errno == EINTR))
			;
		if (ret) {
			fail("Error in semop unlock");
			res = errno;
			break;
		}
	}
	shmdt(mem);
	return res;
}

int main(int argc, char **argv)
{
	key_t key;
	int sem, shm, pid1, pid2;
	int fail_count = 0;
	uint8_t *mem;
	uint32_t crc;
	int ret;

	test_init(argc, argv);

	key = ftok(argv[0], 822155650);
	if (key == -1) {
		pr_perror("Can't make key");
		goto out;
	}

	sem = semget(key, 1, 0777 | IPC_CREAT | IPC_EXCL);
	if (sem == -1) {
		pr_perror("Can't get sem");
		goto out;
	}

	if (semctl(sem, 0, SETVAL, 1) == -1) {
		pr_perror("Can't init sem");
		fail_count++;
		goto out_sem;
	}

	shm = shmget(key, shmem_size, 0777 | IPC_CREAT | IPC_EXCL);
	if (shm == -1) {
		pr_perror("Can't get shm");
		fail_count++;
		goto out_sem;
	}

	mem = shmat(shm, NULL, 0);
	if (mem == (void *)-1) {
		pr_perror("Can't attach shm");
		fail_count++;
		goto out_shm;
	}

	poison_area((int *)mem);

	pid1 = test_fork();
	if (pid1 == -1) {
		pr_perror("Can't fork 1st time");
		goto out_shdt;
	} else if (pid1 == 0)
		exit(child(key));

	pid2 = test_fork();
	if (pid2 == -1) {
		pr_perror("Can't fork 2nd time");
		fail_count++;
		goto out_child;
	} else if (pid2 == 0)
		exit(child(key));

	test_daemon();
	while (test_go()) {
		ret = semop(sem, &lock, 1);
		if (ret) {
			if (errno == EINTR)
				continue;
			fail_count++;
			fail("Error in semop lock");
			break;
		}
		if (mem[0] != POISON) {
			crc = INIT_CRC;
			if (datachk(mem, shmem_size, &crc)) {
				fail_count++;
				fail("Semaphore protection is broken or "
				     "shmem pages are messed");
				semop(sem, &unlock, 1);
				break;
			}
			poison_area((int *)mem);
		}
		while ((ret = semop(sem, &unlock, 1)) && (errno == EINTR))
			;
		if (ret) {
			fail_count++;
			fail("Error in semop unlock");
			break;
		}
	}
	test_waitsig();

	kill(pid2, SIGTERM);
	waitpid(pid2, &ret, 0);
	if (!WIFEXITED(ret)) {
		fail_count++;
		pr_perror("Child 2 was killed");
	} else if (WEXITSTATUS(ret)) {
		fail_count++;
		pr_perror("Child 2 couldn't inititalise");
	}
out_child:
	kill(pid1, SIGTERM);
	waitpid(pid1, &ret, 0);
	if (!WIFEXITED(ret)) {
		fail_count++;
		pr_perror("Child 1 was killed");
	} else if (WEXITSTATUS(ret)) {
		fail_count++;
		pr_perror("Child 1 couldn't inititalise");
	}
out_shdt:
	shmdt(mem);
out_shm:
	shmctl(shm, IPC_RMID, NULL);
out_sem:
	semctl(sem, 1, IPC_RMID);
	if (fail_count == 0)
		pass();
out:
	return 0;
}
