#define _GNU_SOURCE
#include <unistd.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <signal.h>
#include <setjmp.h>

#include "zdtmtst.h"

const char *test_doc="Tests mprotected SYSVIPC shmems";
const char *test_author="Pavel Emelyanov <xemul@openvz.org>";

static sigjmp_buf segv_ret;		/* we need sig*jmp stuff, otherwise SIGSEGV will reset our handler */
static void segfault(int signo)
{
	siglongjmp(segv_ret, 1);
}

static int check_prot(char *ptr, char val, int prot)
{
	if (signal(SIGSEGV, segfault) == SIG_ERR) {
		fail("setting SIGSEGV handler failed: %m\n");
		return -1;
	}

	if (!sigsetjmp(segv_ret, 1)) {
		if (*ptr != val) {
			fail("read value doesn't match what I wrote");
			return -1;
		}
		if (!(prot & PROT_READ)) {
			fail("PROT_READ bypassed\n");
			return -1;
		}
	} else		/* we come here on return from SIGSEGV handler */
		if (prot & PROT_READ) {
			fail("PROT_READ rejected\n");
			return -1;
		}

	if (!sigsetjmp(segv_ret, 1)) {
		*ptr = val;
		if (!(prot & PROT_WRITE)) {
			fail("PROT_WRITE bypassed\n");
			return -1;
		}
	} else		/* we come here on return from SIGSEGV handler */
		if (prot & PROT_WRITE) {
			fail("PROT_WRITE rejected\n");
			return -1;
		}

	if (signal(SIGSEGV, SIG_DFL) == SIG_ERR) {
		fail("restoring SIGSEGV handler failed: %m\n");
		return -1;
	}

	return 0;
}
int main(int argc, char **argv)
{
	key_t key;
	int id, f = 0;
	char *mem;

	test_init(argc, argv);

	key = ftok(argv[0], 812135646);
	if (key == -1) {
		pr_perror("Can't make key");
		goto out;
	}

	id = shmget(key, 2 * PAGE_SIZE, 0777 | IPC_CREAT | IPC_EXCL);
	if (id == -1) {
		pr_perror("Can't make seg");
		goto out;
	}

	mem = shmat(id, NULL, 0);
	if (mem == (void *)-1) {
		pr_perror("Can't shmat");
		goto out_rm;
	}

	mem[0] = 'R';
	mem[PAGE_SIZE] = 'W';

	if (mprotect(mem, PAGE_SIZE, PROT_READ)) {
		pr_perror("Can't mprotect shmem");
		goto out_dt;
	}

	test_daemon();
	test_waitsig();

	if (check_prot(mem, 'R', PROT_READ))
		f++;
	if (check_prot(mem + PAGE_SIZE, 'W', PROT_READ | PROT_WRITE))
		f++;


	if (!f)
		pass();
	else
		fail("Some checks failed");

out_dt:
	shmdt(mem);
out_rm:
	shmctl(id, IPC_RMID, NULL);
out:
	return 0;
}
