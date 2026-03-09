#include <errno.h>
#include <setjmp.h>
#include <signal.h>
#include <stdbool.h>
#include <sys/mman.h>
#include <unistd.h>

#include "pkey-helpers.h"
#include "zdtmtst.h"

const char *test_doc = "Check execute-only restore while user pkeys are also active";
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
	int pagesize;
	int key_user = -1;
	int pkey_exec_before = 0;
	int pkey_exec_after = 0;
	bool has_exec_pkey_before = false;
	bool has_exec_pkey_after = false;
	unsigned char *exec_map = MAP_FAILED;
	unsigned char *user_map = MAP_FAILED;

	test_init(argc, argv);

	key_user = sys_pkey_alloc(0, 0);
	if (key_user < 0) {
		if (errno == ENOSPC || errno == ENOSYS) {
			skip("pkey is unavailable");
			return 0;
		}
		pr_perror("pkey_alloc(user_key) failed");
		return 1;
	}

	pagesize = getpagesize();
	exec_map = mmap(NULL, pagesize, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	user_map = mmap(NULL, pagesize, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (exec_map == MAP_FAILED || user_map == MAP_FAILED) {
		pr_perror("mmap failed");
		goto err;
	}

	if (sys_pkey_mprotect(user_map, pagesize, PROT_READ | PROT_WRITE, key_user)) {
		pr_perror("pkey_mprotect(user_map, user_key) failed");
		goto err;
	}

	/* x86 RET */
	exec_map[0] = 0xC3;
	if (mprotect(exec_map, pagesize, PROT_EXEC)) {
		pr_perror("mprotect(exec_map, PROT_EXEC) failed");
		goto err;
	}

	if (read_vma_pkey(exec_map, &pkey_exec_before, &has_exec_pkey_before))
		goto err_read_before;

	if (!has_exec_pkey_before || pkey_exec_before <= 0) {
		skip("execute-only pkey is unavailable on this kernel/config");
		goto skip_ok;
	}

	if (run_code(exec_map)) {
		fail("execute from PROT_EXEC mapping failed before C/R");
		goto err;
	}

	if (expect_read_fault(exec_map) != 0) {
		skip("execute-only semantics are not enforced in this environment");
		goto skip_ok;
	}

	test_daemon();
	test_waitsig();

	if (sys_pkey_mprotect(user_map, pagesize, PROT_READ | PROT_WRITE, key_user)) {
		pr_perror("pkey_mprotect(user_map, user_key) failed after C/R");
		goto err;
	}

	if (run_code(exec_map)) {
		fail("execute from PROT_EXEC mapping failed after C/R");
		goto err;
	}

	if (expect_read_fault(exec_map) != 0) {
		fail("PROT_EXEC mapping became readable after C/R");
		goto err;
	}

	if (read_vma_pkey(exec_map, &pkey_exec_after, &has_exec_pkey_after))
		goto err_read_after;

	if (!has_exec_pkey_after || pkey_exec_after <= 0) {
		fail("execute-only mapping lost pkey metadata after C/R");
		goto err;
	}

	munmap(exec_map, pagesize);
	munmap(user_map, pagesize);
	sys_pkey_free(key_user);
	pass();
	return 0;

skip_ok:
	if (exec_map != MAP_FAILED)
		munmap(exec_map, pagesize);
	if (user_map != MAP_FAILED)
		munmap(user_map, pagesize);
	if (key_user >= 0)
		sys_pkey_free(key_user);
	return 0;

err:
	if (exec_map != MAP_FAILED)
		munmap(exec_map, pagesize);
	if (user_map != MAP_FAILED)
		munmap(user_map, pagesize);
	if (key_user >= 0)
		sys_pkey_free(key_user);
	return 1;

err_read_before:
	pr_perror("read_vma_pkey(before C/R) failed");
	goto err;

err_read_after:
	pr_perror("read_vma_pkey(after C/R) failed");
	goto err;
}

#else

int main(int argc, char **argv)
{
	test_init(argc, argv);
	skip("Unsupported arch");
	return 0;
}

#endif
