/*
 * test for rseq() syscall
 * See also https://www.efficios.com/blog/2019/02/08/linux-restartable-sequences/
 * https://github.com/torvalds/linux/commit/d7822b1e24f2df5df98c76f0e94a5416349ff759
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <pthread.h>
#include <syscall.h>

#include "zdtmtst.h"

#ifdef __has_include
#if __has_include("sys/rseq.h")
#include <sys/rseq.h>
#endif
#endif

#if defined(__x86_64__)

#if defined(RSEQ_SIG)
static inline void *__criu_thread_pointer(void)
{
#if __GNUC_PREREQ(11, 1)
	return __builtin_thread_pointer();
#else
	void *__result;
#ifdef __x86_64__
	__asm__("mov %%fs:0, %0" : "=r"(__result));
#else
	__asm__("mov %%gs:0, %0" : "=r"(__result));
#endif /* __x86_64__ */
	return __result;
#endif /* !GCC 11 */
}

static inline void unregister_glibc_rseq(void)
{
	struct rseq *rseq = (struct rseq *)((char *)__criu_thread_pointer() + __rseq_offset);

	/* hack: mark glibc rseq structure as failed to register */
	rseq->cpu_id = RSEQ_CPU_ID_REGISTRATION_FAILED;

	/* unregister rseq */
	syscall(__NR_rseq, (void *)rseq, __rseq_size, 1, RSEQ_SIG);
}
#else
static inline void unregister_glibc_rseq(void)
{
}
#endif /* defined(RSEQ_SIG) */

const char *test_doc = "Check that rseq() basic C/R works";
const char *test_author = "Alexander Mikhalitsyn <alexander.mikhalitsyn@virtuozzo.com>";

/* some useful definitions from kernel uapi */
#ifndef RSEQ_SIG

enum rseq_flags {
	RSEQ_FLAG_UNREGISTER = (1 << 0),
};

struct rseq {
	uint32_t cpu_id_start;
	uint32_t cpu_id;
	uint64_t rseq_cs;
	uint32_t flags;
} __attribute__((aligned(4 * sizeof(uint64_t))));

#define RSEQ_SIG 0x53053053

#endif /* RSEQ_SIG */

#ifndef __NR_rseq
#define __NR_rseq 334
#endif
/* EOF */

static __thread volatile struct rseq __rseq_abi;

static int sys_rseq(volatile struct rseq *rseq_abi, uint32_t rseq_len, int flags, uint32_t sig)
{
	return syscall(__NR_rseq, rseq_abi, rseq_len, flags, sig);
}

static void register_thread(void)
{
	int rc;
	unregister_glibc_rseq();
	rc = sys_rseq(&__rseq_abi, sizeof(struct rseq), 0, RSEQ_SIG);
	if (rc) {
		fail("Failed to register rseq");
		exit(1);
	}
}

static void check_thread(void)
{
	int rc;
	rc = sys_rseq(&__rseq_abi, sizeof(struct rseq), 0, RSEQ_SIG);
	if (!(rc && errno == EBUSY)) {
		fail("Failed to check rseq %d", rc);
		exit(1);
	}
}

int main(int argc, char *argv[])
{
	test_init(argc, argv);

	register_thread();

	test_daemon();
	test_waitsig();

	check_thread();

	pass();
	return 0;
}

#else /* #if defined(__x86_64__) */

int main(int argc, char *argv[])
{
	test_init(argc, argv);
	skip("Unsupported arch");
	test_daemon();
	test_waitsig();
	pass();
	return 0;
}

#endif /* #if defined(__x86_64__) */