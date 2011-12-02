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

const char *test_doc="Tests detached shmems migrate fine";
const char *test_author="Andrew Vagin <avagin@parallels.com>";

#define DEF_MEM_SIZE	(40960)
unsigned int shmem_size = DEF_MEM_SIZE;
TEST_OPTION(shmem_size, uint, "Size of shared memory segment", 0);

#define INIT_CRC	(~0)

int main(int argc, char **argv)
{
	key_t key;
	int shm;
	int fail_count = 0;
	uint8_t *mem;
	uint32_t crc;
	int ret;

	test_init(argc, argv);

	key = ftok(argv[0], 822155666);
	if (key == -1) {
		err("Can't make key");
		goto out;
	}

	shm = shmget(key, shmem_size, 0777 | IPC_CREAT | IPC_EXCL);
	if (shm == -1) {
		err("Can't get shm");
		fail_count++;
		goto out;
	}

	mem = shmat(shm, NULL, 0);
	if (mem == (void *)-1) {
		err("Can't attach shm");
		fail_count++;
		goto out_shm;
	}


	test_daemon();

	crc = INIT_CRC;
	datagen(mem, shmem_size, &crc);
	ret = shmdt(mem);
	if (ret) {
		err("Can't detach shm");
		fail_count++;
		goto out_shm;
	}

	test_waitsig();

	mem = shmat(shm, NULL, 0);
	if (mem == (void *)-1) {
		err("Can't attach shm");
		fail_count++;
		goto out_shm;
	}

	crc = INIT_CRC;
	if (datachk(mem, shmem_size, &crc)) {
		fail_count++;
		fail("shmem data are corrupted");
	}

	shmdt(mem);
out_shm:
	shmctl(shm, IPC_RMID, NULL);
	if (fail_count == 0)
		pass();
out:
	return 0;
}
