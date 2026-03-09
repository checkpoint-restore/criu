#include <errno.h>
#include <setjmp.h>
#include <signal.h>
#include <stdbool.h>
#include <sys/mman.h>
#include <unistd.h>

#include "pkey-helpers.h"
#include "zdtmtst.h"

const char *test_doc = "Check execute-only VMA semantics survive C/R";
const char *test_author = "CRIU Team";

#if defined(__x86_64__)

static sigjmp_buf segv_ret;

static void segv_handler(int signo)
{
	(void)signo;
	siglongjmp(segv_ret, 1);
}

static int expect_read_fault(void *addr)
{
	struct sigaction sa_old;
	struct sigaction sa_new = {
		.sa_handler = segv_handler,
	};
	volatile unsigned char x;

	sigemptyset(&sa_new.sa_mask);
	sa_new.sa_flags = 0;
	if (sigaction(SIGSEGV, &sa_new, &sa_old)) {
		pr_perror("sigaction(SIGSEGV) failed");
		return -1;
	}

	if (!sigsetjmp(segv_ret, 1)) {
		x = *(volatile unsigned char *)addr;
		(void)x;
		sigaction(SIGSEGV, &sa_old, NULL);
		return 1;
	}

	sigaction(SIGSEGV, &sa_old, NULL);
	return 0;
}

static int run_code(void *addr)
{
	void (*fn)(void) = addr;

	fn();
	return 0;
}

int main(int argc, char **argv)
{
	int pagesize, pkey_before = 0, pkey_after = 0;
	bool has_pkey_before = false, has_pkey_after = false;
	unsigned char *code = MAP_FAILED;

	test_init(argc, argv);

	pagesize = getpagesize();
	code = mmap(NULL, pagesize, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (code == MAP_FAILED) {
		pr_perror("mmap failed");
		return 1;
	}

	/* x86 RET instruction; enough for a callable function body. */
	code[0] = 0xC3;

	if (mprotect(code, pagesize, PROT_EXEC)) {
		pr_perror("mprotect(PROT_EXEC) failed");
		munmap(code, pagesize);
		return 1;
	}

	if (read_vma_pkey(code, &pkey_before, &has_pkey_before)) {
		pr_perror("read_vma_pkey(before C/R) failed");
		munmap(code, pagesize);
		return 1;
	}

	if (!has_pkey_before || pkey_before <= 0) {
		skip("execute-only pkey is unavailable on this kernel/config");
		munmap(code, pagesize);
		return 0;
	}

	if (run_code(code)) {
		fail("execute from PROT_EXEC mapping failed before C/R");
		munmap(code, pagesize);
		return 1;
	}

	if (expect_read_fault(code) != 0) {
		skip("execute-only semantics are not enforced in this environment");
		munmap(code, pagesize);
		return 0;
	}

	test_daemon();
	test_waitsig();

	if (run_code(code)) {
		fail("execute from PROT_EXEC mapping failed after C/R");
		munmap(code, pagesize);
		return 1;
	}

	if (expect_read_fault(code) != 0) {
		fail("PROT_EXEC mapping became readable after C/R");
		munmap(code, pagesize);
		return 1;
	}

	if (read_vma_pkey(code, &pkey_after, &has_pkey_after)) {
		pr_perror("read_vma_pkey(after C/R) failed");
		munmap(code, pagesize);
		return 1;
	}

	if (!has_pkey_after || pkey_after <= 0) {
		fail("execute-only mapping lost pkey metadata after C/R");
		munmap(code, pagesize);
		return 1;
	}

	munmap(code, pagesize);
	pass();
	return 0;
}

#else

int main(int argc, char **argv)
{
	test_init(argc, argv);
	skip("Unsupported arch");
	return 0;
}

#endif
