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
#include "lock.h"

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
	unsigned int size = __rseq_size;

	/* hack: mark glibc rseq structure as failed to register */
	rseq->cpu_id = RSEQ_CPU_ID_REGISTRATION_FAILED;

	/* unregister rseq */
	if (__rseq_size < 32)
		size = 32;
	syscall(__NR_rseq, (void *)rseq, size, 1, RSEQ_SIG);
}
#else
static inline void unregister_glibc_rseq(void)
{
}
#endif /* defined(RSEQ_SIG) */

const char *test_doc = "Check rseq() critical section abort during C/R";
const char *test_author = "Alexander Mikhalitsyn <alexander.mikhalitsyn@virtuozzo.com>";

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

struct rseq_cs {
	/* Version of this structure. */
	uint32_t version;
	/* enum rseq_cs_flags */
	uint32_t flags;
	uint64_t start_ip;
	/* Offset from start_ip. */
	uint64_t post_commit_offset;
	uint64_t abort_ip;
} __attribute__((aligned(4 * sizeof(__u64))));

#define RSEQ_SIG 0x53053053

#endif /* RSEQ_SIG */

#ifndef __NR_rseq
#define __NR_rseq 334
#endif
/* EOF */

extern futex_t sig_received;

static __thread volatile struct rseq __rseq_abi __attribute__((aligned(64)));
static __thread volatile struct rseq_cs __rseq_cs __attribute__((aligned(64)));

static __thread volatile int rseq_state = 0;

static int sys_rseq(volatile struct rseq *rseq_abi, uint32_t rseq_len, int flags, uint32_t sig)
{
	return syscall(__NR_rseq, rseq_abi, rseq_len, flags, sig);
}

/*
 * Return the rseq registration size. Starting with Linux 7.0,
 * AT_RSEQ_ALIGN is 64 but the feature size is 33, so sizeof(struct rseq)
 * (padded to alignment) no longer matches the registration size the kernel
 * expects. Use __rseq_size when available, clamped to a minimum of 32
 * for older kernels.
 */
static uint32_t rseq_reg_size(void)
{
#if defined(RSEQ_SIG) && defined(__rseq_size)
	if (__rseq_size)
		return (__rseq_size < 32) ? 32 : __rseq_size;
#endif
	return sizeof(struct rseq);
}

static unsigned long mmap_min_addr = 0x10000UL;

/*
 * Machine code for x86_64 that emulates:
 *   __rseq_abi.rseq_cs = &__rseq_cs;
 *   rseq_state = 1;
 *   while (futex_get(f) == 0) {
 *       if (__rseq_abi.rseq_cs != &__rseq_cs)
 *           return;
 *   }
 *   __rseq_abi.rseq_cs = 0;
 *   rseq_state = 0;
 *
 * Disassembly:
 *   0x0:  48 89 37             mov    %rsi,(%rdi)   // set __rseq_abi.rseq_cs = &__rseq_cs
 *   0x3:  c7 01 01 00 00 00    movl   $1,(%rcx)     // set rseq_state = 1
 *   0x9:  48 39 37             cmp    %rsi,(%rdi)   // check if __rseq_abi.rseq_cs == &__rseq_cs
 *   0xc:  75 13                jne    0x21          // if not equal, break out (jump to ret)
 *   0xe:  8b 02                mov    (%rdx),%eax   // load *f
 *   0x10: 85 c0                test   %eax,%eax     // check if 0
 *   0x12: 74 f5                je     0x9           // spin while *f == 0
 *   0x14: 48 c7 07 00 00 00 00 movq   $0,(%rdi)     // clear __rseq_abi.rseq_cs on exit
 *   0x1b: c7 01 00 00 00 00    movl   $0,(%rcx)     // set rseq_state = 0
 *   0x21: c3                   ret                  // return
 */
static const uint8_t test_go_rseq_code[] = {
	0x48, 0x89, 0x37,
	0xc7, 0x01, 0x01, 0x00, 0x00, 0x00,
	0x48, 0x39, 0x37,
	0x75, 0x13,
	0x8b, 0x02,
	0x85, 0xc0,
	0x74, 0xf5,
	0x48, 0xc7, 0x07, 0x00, 0x00, 0x00, 0x00,
	0xc7, 0x01, 0x00, 0x00, 0x00, 0x00,
	0xc3,
};

/*
 * Machine code for the rseq abort section:
 *   rseq_state = 0;
 *   return;
 *
 * Disassembly:
 *   0: c7 01 00 00 00 00    movl   $0,(%rcx)     // set rseq_state = 0
 *   6: c3                   ret                  // return
 */
static const uint8_t test_go_rseq_abort_code[] = {
	0xc7, 0x01, 0x00, 0x00, 0x00, 0x00,
	0xc3,
};

static void register_thread(void)
{
	int rc;
	void *addr;

	addr = mmap((void *)mmap_min_addr, 4096, PROT_READ | PROT_WRITE | PROT_EXEC,
		    MAP_FIXED_NOREPLACE | MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
	if (addr == MAP_FAILED)
		addr = mmap(NULL, 4096, PROT_READ | PROT_WRITE | PROT_EXEC,
			    MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
	if (addr == MAP_FAILED) {
		fail("Failed to mmap rseq critical section area");
		exit(1);
	}

	memcpy(addr, test_go_rseq_code, sizeof(test_go_rseq_code));

	__rseq_cs.start_ip = (uint64_t)addr;
	__rseq_cs.post_commit_offset = 2048;
	__rseq_cs.abort_ip = __rseq_cs.start_ip + 2048;
	*((uint32_t *)__rseq_cs.abort_ip - 1) = RSEQ_SIG;
	memcpy((void *)__rseq_cs.abort_ip, test_go_rseq_abort_code,
	       sizeof(test_go_rseq_abort_code));

	unregister_glibc_rseq();
	rc = sys_rseq(&__rseq_abi, rseq_reg_size(), 0, RSEQ_SIG);
	if (rc) {
		fail("Failed to register rseq");
		exit(1);
	}
}

static void check_thread(void)
{
	int rc;
	rc = sys_rseq(&__rseq_abi, rseq_reg_size(), 0, RSEQ_SIG);
	if (!(rc && errno == EBUSY)) {
		fail("Failed to check rseq %d", rc);
		exit(1);
	}
}

static void test_go_rseq(futex_t *f)
{
	void (*fn)(void *, volatile struct rseq_cs *, futex_t *, volatile int *) =
		(void (*)(void *, volatile struct rseq_cs *, futex_t *, volatile int *))__rseq_cs.start_ip;

	while (futex_get(f) == 0) {
		fn((void *)&__rseq_abi.rseq_cs, &__rseq_cs, f, &rseq_state);
		if (rseq_state != 0) {
			fail("rseq_state is %d (expected 0)", rseq_state);
			exit(1);
		}
	}
}

static void *tfunc(void *args)
{
	register_thread();
	test_go_rseq(&sig_received);
	check_thread();
	return NULL;
}

int main(int argc, char *argv[])
{
	pthread_t th;
	int ret;

	test_init(argc, argv);

	ret = pthread_create(&th, NULL, tfunc, NULL);
	if (ret) {
		pr_err("pthread_create -> %d\n", ret);
		return 1;
	}

	register_thread();

	test_daemon();
	test_go_rseq(&sig_received);

	ret = pthread_join(th, NULL);
	if (ret) {
		pr_err("pthread_join -> %d\n", ret);
		return 1;
	}
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
