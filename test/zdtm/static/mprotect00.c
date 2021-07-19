#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <sys/mman.h>
#include <setjmp.h>
#include <limits.h>

#include "zdtmtst.h"

const char *test_doc = "Check that memory protection migrates correctly\n";
const char *test_author = "Roman Kagan <rkagan@parallels.com>";

const static int prots[] = {
	PROT_NONE,
	PROT_READ,
	/* PROT_WRITE, */ /* doesn't work w/o READ */
		PROT_READ | PROT_WRITE,
	PROT_READ | PROT_WRITE | PROT_EXEC,
};
#define NUM_MPROTS sizeof(prots) / sizeof(int)

static sigjmp_buf segv_ret; /* we need sig*jmp stuff, otherwise SIGSEGV will reset our handler */
static void segfault(int signo)
{
	siglongjmp(segv_ret, 1);
}

static int check_prot(char *ptr, int prot)
{
	if (signal(SIGSEGV, segfault) == SIG_ERR) {
		fail("setting SIGSEGV handler failed");
		return -1;
	}

	if (!sigsetjmp(segv_ret, 1)) {
		if (ptr[10] != 0) {
			fail("read value doesn't match what I wrote");
			return -1;
		}
		if (!(prot & PROT_READ)) {
			fail("PROT_READ bypassed");
			return -1;
		}
	} else /* we come here on return from SIGSEGV handler */
		if (prot & PROT_READ) {
		fail("PROT_READ rejected");
		return -1;
	}

	if (!sigsetjmp(segv_ret, 1)) {
		ptr[20] = 67;
		if (!(prot & PROT_WRITE)) {
			fail("PROT_WRITE bypassed");
			return -1;
		}
	} else /* we come here on return from SIGSEGV handler */
		if (prot & PROT_WRITE) {
		fail("PROT_WRITE rejected");
		return -1;
	}

	if (signal(SIGSEGV, SIG_DFL) == SIG_ERR) {
		fail("restoring SIGSEGV handler failed");
		return -1;
	}

	return 0;
}

int main(int argc, char **argv)
{
	char *ptr, *ptr_aligned;
	int pagesize;
	int i;

	test_init(argc, argv);

	pagesize = sysconf(_SC_PAGESIZE);
	if (pagesize < 0) {
		pr_perror("can't get PAGE_SIZE");
		exit(1);
	}

	ptr = mmap(NULL, pagesize * (NUM_MPROTS + 1), PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
	if (ptr == MAP_FAILED) {
		pr_perror("calloc failed");
		return -1;
	}

	ptr_aligned = (char *)(((unsigned long)ptr + pagesize - 1) & ~(pagesize - 1));

	for (i = 0; i < NUM_MPROTS; i++)
		if (mprotect(ptr_aligned + pagesize * i, pagesize / 2, prots[i]) < 0) {
			pr_perror("mprotect failed");
			exit(1);
		}

	test_daemon();
	test_waitsig();

	for (i = 0; i < NUM_MPROTS; i++)
		if (check_prot(ptr_aligned + pagesize * i, prots[i]))
			goto out;

	pass();
out:
	return 0;
}
