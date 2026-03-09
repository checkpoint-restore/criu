#include <errno.h>
#include <setjmp.h>
#include <signal.h>
#include <stdint.h>
#include <sys/mman.h>
#include <unistd.h>

#include "pkey-helpers.h"
#include "zdtmtst.h"

const char *test_doc = "Check PKRU state survives C/R after pkey restore operations";
const char *test_author = "CRIU Team";

#if defined(__x86_64__)

#ifndef PKEY_DISABLE_WRITE
#define PKEY_DISABLE_WRITE 0x2
#endif

static sigjmp_buf segv_ret;

static inline uint32_t rdpkru(void)
{
	uint32_t pkru;

	asm volatile(".byte 0x0f, 0x01, 0xee" : "=a"(pkru) : "c"(0) : "edx");
	return pkru;
}

static inline void wrpkru(uint32_t pkru)
{
	asm volatile(".byte 0x0f, 0x01, 0xef" : : "a"(pkru), "c"(0), "d"(0));
}

static void segv_handler(int signo)
{
	(void)signo;
	siglongjmp(segv_ret, 1);
}

static int expect_write_fault(void *addr)
{
	struct sigaction sa_old;
	struct sigaction sa_new = {
		.sa_handler = segv_handler,
	};

	sigemptyset(&sa_new.sa_mask);
	sa_new.sa_flags = 0;

	if (sigaction(SIGSEGV, &sa_new, &sa_old)) {
		pr_perror("sigaction(SIGSEGV) failed");
		return -1;
	}

	if (!sigsetjmp(segv_ret, 1)) {
		*(volatile unsigned char *)addr = 0xAA;
		sigaction(SIGSEGV, &sa_old, NULL);
		return 1;
	}

	sigaction(SIGSEGV, &sa_old, NULL);
	return 0;
}

int main(int argc, char **argv)
{
	int pagesize;
	int key = -1;
	void *map = MAP_FAILED;
	uint32_t saved_pkru;
	uint32_t blocked_pkru;
	uint32_t shift;
	int ret;

	test_init(argc, argv);

	key = sys_pkey_alloc(0, 0);
	if (key < 0) {
		if (errno == ENOSPC || errno == ENOSYS) {
			skip("pkey is unavailable");
			return 0;
		}

		pr_perror("pkey_alloc failed");
		return 1;
	}

	pagesize = getpagesize();
	map = mmap(NULL, pagesize, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (map == MAP_FAILED) {
		pr_perror("mmap failed");
		sys_pkey_free(key);
		return 1;
	}

	if (sys_pkey_mprotect(map, pagesize, PROT_READ | PROT_WRITE, key)) {
		pr_perror("pkey_mprotect(map, key) failed");
		munmap(map, pagesize);
		sys_pkey_free(key);
		return 1;
	}

	saved_pkru = rdpkru();
	shift = 2U * (uint32_t)key;
	blocked_pkru = saved_pkru | ((uint32_t)PKEY_DISABLE_WRITE << shift);
	wrpkru(blocked_pkru);

	ret = expect_write_fault(map);
	if (ret != 0) {
		fail("write fault expectation before C/R failed: %d", ret);
		goto err;
	}

	test_daemon();
	test_waitsig();

	ret = expect_write_fault(map);
	if (ret != 0) {
		fail("write fault expectation after C/R failed: %d", ret);
		goto err;
	}

	/* Clear WD bit and verify mapping is writable again. */
	wrpkru(saved_pkru);
	*(volatile unsigned char *)map = 0x55;

	munmap(map, pagesize);
	sys_pkey_free(key);
	pass();
	return 0;

err:
	wrpkru(saved_pkru);
	munmap(map, pagesize);
	if (key >= 0)
		sys_pkey_free(key);
	return 1;
}

#else

int main(int argc, char **argv)
{
	test_init(argc, argv);
	skip("Unsupported arch");
	return 0;
}

#endif
