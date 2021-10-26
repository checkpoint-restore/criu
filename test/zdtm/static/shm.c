#include <sched.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <signal.h>
#include <errno.h>

#include "zdtmtst.h"

const char *test_doc = "Tests detached shmems migrate fine";
const char *test_author = "Stanislav Kinsbursky <skinsbursky@parallels.com>";

#define DEF_MEM_SIZE (40960)
unsigned int shmem_size = DEF_MEM_SIZE;
TEST_OPTION(shmem_size, uint, "Size of shared memory segment", 0);

#define INIT_CRC (~0)

static int fill_shm_seg(int id, size_t size)
{
	uint8_t *mem;
	uint32_t crc = INIT_CRC;

	mem = shmat(id, NULL, 0);
	if (mem == (void *)-1) {
		pr_perror("Can't attach shm");
		return -1;
	}

	datagen(mem, size, &crc);

	if (shmdt(mem) < 0) {
		pr_perror("Can't detach shm");
		return -1;
	}
	return 0;
}

static int get_shm_seg(int key, size_t size, unsigned int flags)
{
	int id;

	id = shmget(key, size, 0777 | flags);
	if (id == -1) {
		pr_perror("Can't get shm");
		return -1;
	}
	return id;
}

static int prepare_shm(int key, size_t size)
{
	int id, flag = 0;

#ifdef ZDTM_HUGETLB
	flag = SHM_HUGETLB;
#endif

	id = get_shm_seg(key, size, IPC_CREAT | IPC_EXCL | flag);
	if (id == -1) {
		return -1;
	}
	if (fill_shm_seg(id, size) < 0)
		return -1;
	return id;
}

static int check_shm_id(int id, size_t size)
{
	uint8_t *mem;
	uint32_t crc = INIT_CRC;

	mem = shmat(id, NULL, 0);
	if (mem == (void *)-1) {
		pr_perror("Can't attach shm");
		return -1;
	}
	crc = INIT_CRC;
	if (datachk(mem, size, &crc)) {
		fail("shmem data are corrupted");
		return -1;
	}
	if (shmdt(mem) < 0) {
		pr_perror("Can't detach shm");
		return -1;
	}
	return 0;
}

static int check_shm_key(int key, size_t size)
{
	int id;

	id = get_shm_seg(key, size, 0);
	if (id < 0)
		return -1;
	return check_shm_id(id, size);
}

int main(int argc, char **argv)
{
	key_t key;
	int shm;
	int fail_count = 0;
	int ret = -1;
	dev_t dev;

	void *mem;
	uint32_t crc = INIT_CRC;

	test_init(argc, argv);

#ifdef ZDTM_SHM_UNALIGNED
	key = ftok(argv[0], 822155666);
#else
	key = ftok(argv[0], 822155667);
#endif
	if (key == -1) {
		pr_perror("Can't make key");
		goto out;
	}

	shm = prepare_shm(key, shmem_size);
	if (shm == -1) {
		pr_err("Can't prepare shm (1)\n");
		goto out;
	}

	mem = shmat(shm, NULL, 0);
	if (mem == (void *)-1) {
		pr_perror("Can't shmat");
		goto out;
	}

	dev = get_mapping_dev(mem);
	if (dev == (dev_t)-1) {
		fail("Can't get mapping dev");
		return -1;
	}

	test_daemon();
	test_waitsig();

	ret = check_shm_id(shm, shmem_size);
	if (ret < 0) {
		fail("ID check (1) failed");
		fail_count++;
		goto out_shm;
	}

	ret = check_shm_key(key, shmem_size);
	if (ret < 0) {
		fail("KEY check failed");
		fail_count++;
		goto out_shm;
	}

	if (datachk(mem, shmem_size, &crc)) {
		fail("shmem data is corrupted");
		return -1;
	}

	if (dev != get_mapping_dev(mem)) {
		fail("Mapping dev mismatch");
		return -1;
	}

	if (shmdt(mem) < 0) {
		pr_perror("Can't detach shm");
		return -1;
	}

	ret = shmctl(shm, IPC_RMID, NULL);
	if (ret < 0) {
		fail("Failed (1) to destroy segment");
		fail_count++;
		goto out_shm;
	}
	/*
	 * Code below checks that it's still possible to create new IPC SHM
	 * segments
	 */
	shm = prepare_shm(key, shmem_size);
	if (shm == -1) {
		fail("Can't prepare shm (2)");
		fail_count++;
		goto out;
	}

	ret = check_shm_id(shm, shmem_size);
	if (ret < 0) {
		fail("ID check (2) failed");
		fail_count++;
		goto out_shm;
	}

out_shm:
	ret = shmctl(shm, IPC_RMID, NULL);
	if (ret < 0) {
		fail("Failed (2) to destroy segment");
		fail_count++;
	}
	if (fail_count == 0)
		pass();
out:
	return ret;
}
