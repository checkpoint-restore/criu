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

#if defined(__x86_64__) && defined(RSEQ_SIG)
static inline void *thread_pointer(void)
{
	void *result;
	asm("mov %%fs:0, %0" : "=r"(result));
	return result;
}

static inline void unregister_old_rseq(void)
{
	/* unregister rseq */
	syscall(__NR_rseq, (void *)((char *)thread_pointer() + __rseq_offset), __rseq_size, 1, RSEQ_SIG);
}
#else
static inline void unregister_old_rseq(void)
{
}
#endif

const char *test_doc = "rseq() transition test";
const char *test_author = "Alexander Mikhalitsyn <alexander.mikhalitsyn@virtuozzo.com>";
/*
 * Thanks to Mathieu Desnoyers <mathieu.desnoyers@efficios.com> (rseq author)
 * who helped me with review and debugging the problem on the Alpine Linux.
 *
 * parts of code borrowed from
 * https://www.efficios.com/blog/2019/02/08/linux-restartable-sequences/
 */

/* some useful definitions from kernel uapi */
#ifndef RSEQ_SIG

enum rseq_flags {
	RSEQ_FLAG_UNREGISTER = (1 << 0),
};

enum rseq_cs_flags_bit {
	RSEQ_CS_FLAG_NO_RESTART_ON_PREEMPT_BIT = 0,
	RSEQ_CS_FLAG_NO_RESTART_ON_SIGNAL_BIT = 1,
	RSEQ_CS_FLAG_NO_RESTART_ON_MIGRATE_BIT = 2,
};

enum rseq_cs_flags {
	RSEQ_CS_FLAG_NO_RESTART_ON_PREEMPT = (1U << RSEQ_CS_FLAG_NO_RESTART_ON_PREEMPT_BIT),
	RSEQ_CS_FLAG_NO_RESTART_ON_SIGNAL = (1U << RSEQ_CS_FLAG_NO_RESTART_ON_SIGNAL_BIT),
	RSEQ_CS_FLAG_NO_RESTART_ON_MIGRATE = (1U << RSEQ_CS_FLAG_NO_RESTART_ON_MIGRATE_BIT),
};

struct rseq {
	uint32_t cpu_id_start;
	uint32_t cpu_id;
	uint64_t rseq_cs;
	uint32_t flags;
} __attribute__((aligned(4 * sizeof(uint64_t))));

#define RSEQ_SIG 0x53053053

#endif

#ifndef __NR_rseq
#define __NR_rseq 334
#endif
/* EOF */

static volatile struct rseq *rseq_ptr;
static __thread volatile struct rseq __rseq_abi;

static int sys_rseq(volatile struct rseq *rseq_abi, uint32_t rseq_len, int flags, uint32_t sig)
{
	return syscall(__NR_rseq, rseq_abi, rseq_len, flags, sig);
}

static void register_thread(void)
{
	int rc;
	unregister_old_rseq();
	rc = sys_rseq(rseq_ptr, sizeof(struct rseq), 0, RSEQ_SIG);
	if (rc) {
		fail("Failed to register rseq");
		exit(1);
	}
}

static void check_thread(void)
{
	int rc;
	rc = sys_rseq(rseq_ptr, sizeof(struct rseq), 0, RSEQ_SIG);
	if (!(rc && errno == EBUSY)) {
		fail("Failed to check rseq %d", rc);
		exit(1);
	}
}

#define RSEQ_ACCESS_ONCE(x) (*(__volatile__ __typeof__(x) *)&(x))

#define rseq_after_asm_goto() asm volatile("" : : : "memory")

static int rseq_addv(intptr_t *v, intptr_t count, int cpu)
{
	double a = 10000000000000000.0;
	double b = -1;
	uint64_t rseq_cs1 = 0, rseq_cs2 = 0;

	/* clang-format off */
	__asm__ __volatile__ goto(
		".pushsection __rseq_table, \"aw\"\n\t"
		".balign 32\n\t"
		"cs_obj:\n\t"
		/* version, flags */
		".long 0, 0\n\t"
		/* start_ip, post_commit_offset, abort_ip */
		".quad 1f, (2f-1f), 4f\n\t"
		".popsection\n\t"
		"fldl %[x]\n\t" /* we have st clobbered */
		"leaq cs_obj(%%rip), %%rax\n\t"
		"1:\n\t"
		"movq %%rax, %[rseq_cs]\n\t"
		"cmpl %[cpu_id], %[current_cpu_id]\n\t"
		"jnz 4f\n\t"
		"addq %[count], %[v]\n\t"	/* final store */
		"mov $10000000, %%rcx\n\t"
		"5:\n\t"
		"fsqrt\n\t" /* heavy instruction */
		"dec %%rcx\n\t"
		"jnz 5b\n\t"
		"movq %%rax, %[rseq_cs_check2]\n\t"
		"movq %[rseq_cs], %%rax\n\t"
		"movq %%rax, %[rseq_cs_check1]\n\t"
		"fstpl %[y]\n\t"
		"2:\n\t"
		".pushsection __rseq_failure, \"ax\"\n\t"
		/* Disassembler-friendly signature: nopl <sig>(%rip). */
		".byte 0x0f, 0xb9, 0x3d\n\t"
		".long 0x53053053\n\t"	/* RSEQ_FLAGS */
		"4:\n\t"
		"fstpl %[y]\n\t"
		"jmp %l[abort]\n\t"
		/*"jmp 1b\n\t"*/
		".popsection\n\t"
		: /* gcc asm goto does not allow outputs */
		: [cpu_id]              "r" (cpu),
		[current_cpu_id]      "m" (rseq_ptr->cpu_id),
		[rseq_cs]             "m" (rseq_ptr->rseq_cs),
		[rseq_cs_check1]       "m" (rseq_cs1),
		[rseq_cs_check2]       "m" (rseq_cs2),
		/* final store input */
		[v]                   "m" (*v),
		[count]               "er" (count),
		[x]			"m" (a),
		[y]			"m" (b)
		: "memory", "cc", "rax", "rcx", "st"
		: abort
	);
	/* clang-format on */
	rseq_after_asm_goto();
	test_msg("exit %lx %lx %f %f\n", rseq_cs1, rseq_cs2, a, b);
	if (rseq_cs1 != rseq_cs2) {
		/*
		 * It means that we finished critical section
		 * *normally* (haven't jumped to abort) but the kernel had cleaned up
		 * rseq_ptr->rseq_cs before we left critical section
		 * and CRIU didn't restore it correctly.
		 * That's a bug picture.
		 */
		return -1;
	}

	return 0;
abort:
	rseq_after_asm_goto();
	test_msg("abort %lx %lx %f %f\n", rseq_cs1, rseq_cs2, a, b);
	return -1;
}

int main(int argc, char *argv[])
{
	int cpu = 0;
	int ret;
	intptr_t *cpu_data;
	long nr_cpus;

	rseq_ptr = &__rseq_abi;
	memset((void *)rseq_ptr, 0, sizeof(struct rseq));

	test_init(argc, argv);
	nr_cpus = sysconf(_SC_NPROCESSORS_ONLN);

	cpu_data = calloc(nr_cpus, sizeof(*cpu_data));
	if (!cpu_data) {
		fail("calloc");
		exit(EXIT_FAILURE);
	}

	register_thread();

	/*
	 * We want to test that RSEQ_CS_FLAG_NO_RESTART_ON_SIGNAL
	 * is handled properly by CRIU, but that flag can be used
	 * only with all another flags set.
	 * Please, refer to
	 * https://github.com/torvalds/linux/blob/ce522ba9/kernel/rseq.c#L192
	 */
#ifdef NORESTART
	rseq_ptr->flags = RSEQ_CS_FLAG_NO_RESTART_ON_PREEMPT | RSEQ_CS_FLAG_NO_RESTART_ON_SIGNAL |
			  RSEQ_CS_FLAG_NO_RESTART_ON_MIGRATE;
#endif

	test_daemon();

	while (test_go()) {
		cpu = RSEQ_ACCESS_ONCE(rseq_ptr->cpu_id_start);
		ret = rseq_addv(&cpu_data[cpu], 2, cpu);

/* NORESTART is NOT set */
#ifndef NORESTART
		/* just ignore abort */
		ret = 0;
#endif

		if (ret)
			break;
	}

	test_waitsig();

	check_thread();

	if (ret)
		fail();
	else
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
