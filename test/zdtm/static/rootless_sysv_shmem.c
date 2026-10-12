#include <stdint.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <unistd.h>

#include "zdtmtst.h"

const char *test_doc = "Check SysV shmem survives C/R in a non-initial user namespace";
const char *test_author = "Deepak Anand <deepakanand1300@gmail.com>";

#define SHMEM_SIZE 40960
#define INIT_CRC   (~0U)

int main(int argc, char **argv)
{
	uint32_t crc = INIT_CRC;
	key_t key;
	int shmid;
	uint8_t *mem;
	int ret = 1;

	test_init(argc, argv);

	key = ftok(argv[0], 842109);
	if (key == -1) {
		pr_perror("Can't make key");
		return 1;
	}

	shmid = shmget(key, SHMEM_SIZE, IPC_CREAT | IPC_EXCL | 0600);
	if (shmid < 0) {
		pr_perror("Can't create SysV shmem");
		return 1;
	}

	mem = shmat(shmid, NULL, 0);
	if (mem == (void *)-1) {
		pr_perror("Can't attach SysV shmem");
		goto out_rm;
	}

	datagen(mem, SHMEM_SIZE, &crc);

	test_daemon();
	test_waitsig();

	crc = INIT_CRC;
	if (datachk(mem, SHMEM_SIZE, &crc)) {
		fail("SysV shmem data corrupted after C/R");
		goto out_dt;
	}

	pass();
	ret = 0;

out_dt:
	if (shmdt(mem) < 0) {
		pr_perror("Can't detach SysV shmem");
		ret = 1;
	}
out_rm:
	if (shmctl(shmid, IPC_RMID, NULL) < 0) {
		pr_perror("Can't remove SysV shmem");
		ret = 1;
	}

	return ret;
}
